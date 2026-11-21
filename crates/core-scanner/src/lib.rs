pub mod hasher;
pub mod matcher;

use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub path: String,
    pub sha256: String,
    pub matched_rule: Option<String>,
}

const TEST_SIGNATURE: &[u8] = b"SENTINEL-TEST-SIGNATURE";

/// Walks a directory and returns any files matching known patterns.
pub fn scan_directory(root: &Path) -> Vec<ScanResult> {
    let mut findings = Vec::new();

    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        if let Ok(true) = matcher::find_signature(path, TEST_SIGNATURE) {
            let hash = hasher::sha256_file(path).unwrap_or_else(|_| "unknown".into());
            findings.push(ScanResult {
                path: path.display().to_string(),
                sha256: hash,
                matched_rule: Some("Test_Suspicious_Pattern".to_string()),
            });
        }
    }

    findings
}