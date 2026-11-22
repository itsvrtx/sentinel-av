pub mod hasher;
pub mod matcher;

use serde::Serialize;
use std::path::Path;
use std::time::Instant;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub path: String,
    pub sha256: String,
    pub matched_rule: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub files_scanned: usize,
    pub duration_ms: u128,
    pub findings: Vec<ScanResult>,
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

    if root.is_file() {
        files_scanned = 1;
        on_file(1, root);
        if let Some(rule_name) = matcher::scan_file_with_rules(&rules, root) {
            let hash = hasher::sha256_file(root).unwrap_or_else(|_| "unknown".into());
            findings.push(ScanResult {
                path: root.display().to_string(),
                sha256: hash,
                matched_rule: Some(rule_name),
            });
        }
    } else {
        for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            files_scanned += 1;
            on_file(files_scanned, path);

            if let Some(rule_name) = matcher::scan_file_with_rules(&rules, path) {
                let hash = hasher::sha256_file(path).unwrap_or_else(|_| "unknown".into());
                findings.push(ScanResult {
                    path: path.display().to_string(),
                    sha256: hash,
                    matched_rule: Some(rule_name),
                });
            }
        }
    }

    Ok(ScanReport {
        files_scanned,
        duration_ms: start.elapsed().as_millis(),
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
        let report = scan_directory_with_progress(&root, &rules, |_count, _path| {})
            .expect("Scan failed");

        assert!(report.files_scanned >= 2);
        assert!(report.findings.len() >= 2);
        let rules_found: Vec<_> = report.findings.iter().filter_map(|f| f.matched_rule.as_deref()).collect();
        assert!(rules_found.contains(&"Test_Suspicious_Pattern"));
        assert!(rules_found.contains(&"EICAR_Test_File"));
    }
}
