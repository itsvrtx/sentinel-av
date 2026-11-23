use crate::ScanResult;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanLogEntry {
    pub timestamp: u64,
    pub target: String,
    pub files_scanned: usize,
    pub duration_ms: u128,
    pub threats_found: usize,
    pub findings: Vec<ScanResult>,
}

pub fn get_default_log_path() -> PathBuf {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        PathBuf::from(local_app_data).join("SentinelAV").join("scan_logs.jsonl")
    } else {
        PathBuf::from("scan_logs.jsonl")
    }
}

/// Appends a new scan report entry to the JSONL log file.
pub fn append_scan_log(
    log_path: &Path,
    target: &str,
    files_scanned: usize,
    duration_ms: u128,
    findings: &[ScanResult],
) -> io::Result<()> {
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let entry = ScanLogEntry {
        timestamp,
        target: target.to_string(),
        files_scanned,
        duration_ms,
        threats_found: findings.len(),
        findings: findings.to_vec(),
    };

    let mut line = serde_json::to_string(&entry)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    line.push('\n');

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    file.write_all(line.as_bytes())?;
    file.flush()
}

/// Reads the most recent log entries up to `max_entries` (newest first).
pub fn read_recent_logs(log_path: &Path, max_entries: usize) -> io::Result<Vec<ScanLogEntry>> {
    if !log_path.exists() {
        return Ok(Vec::new());
    }

    let file = fs::File::open(log_path)?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        if let Ok(l) = line {
            if let Ok(entry) = serde_json::from_str::<ScanLogEntry>(&l) {
                entries.push(entry);
            }
        }
    }

    entries.reverse();
    if entries.len() > max_entries {
        entries.truncate(max_entries);
    }
    Ok(entries)
}

/// Removes log entries that had zero threats detected, keeping only threat detections.
pub fn clear_clean_logs(log_path: &Path) -> io::Result<usize> {
    if !log_path.exists() {
        return Ok(0);
    }
    let all = read_recent_logs(log_path, usize::MAX)?;
    let threats_only: Vec<ScanLogEntry> = all.into_iter().filter(|e| e.threats_found > 0).collect();
    let removed = read_recent_logs(log_path, usize::MAX)?.len().saturating_sub(threats_only.len());

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(log_path)?;

    for entry in threats_only.iter().rev() {
        let mut line = serde_json::to_string(entry)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        line.push('\n');
        file.write_all(line.as_bytes())?;
    }
    file.flush()?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_logger() {
        let temp_dir = std::env::temp_dir();
        let log_file = temp_dir.join("test_sentinel_scan.jsonl");
        let _ = fs::remove_file(&log_file);

        let findings = vec![ScanResult {
            path: "test/file.exe".into(),
            sha256: "hash123".into(),
            matched_rule: Some("Test_Rule".into()),
        }];

        append_scan_log(&log_file, "C:/test_folder", 10, 42, &findings).unwrap();
        let logs = read_recent_logs(&log_file, 10).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].target, "C:/test_folder");
        assert_eq!(logs[0].files_scanned, 10);
        assert_eq!(logs[0].threats_found, 1);

        let _ = fs::remove_file(&log_file);
    }
}
