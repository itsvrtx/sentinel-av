pub mod hasher;
pub mod matcher;

/// Represents the result of scanning a single file.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub path: String,
    pub sha256: String,
    pub matched_rule: Option<String>,
}
