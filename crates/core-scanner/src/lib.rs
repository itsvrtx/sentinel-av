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

/// Walks a directory, runs compiled YARA rules, and calls `on_file` for every file checked.
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

    Ok(ScanReport {
        files_scanned,
        duration_ms: start.elapsed().as_millis(),
        findings,
    })
}