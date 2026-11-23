use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistenceFinding {
    pub path: PathBuf,
    pub is_suspicious: bool,
    pub reason: String,
}

/// Checks if an autostart or startup command targets a high-risk persistence location.
pub fn is_suspicious_persistence_target(command_or_path: &str) -> bool {
    let lower = command_or_path.to_lowercase();
    // High-abuse persistence locations: AppData/Temp, scripts, or encoded commands
    lower.contains("appdata\\local\\temp")
        || lower.contains("appdata/local/temp")
        || lower.contains("\\temp\\")
        || lower.ends_with(".vbs")
        || lower.ends_with(".bat")
        || lower.ends_with(".ps1")
        || lower.contains("-enc")
}

/// Scans a directory (e.g. Windows Startup folder) for suspicious autostart items.
pub fn scan_startup_directory(startup_dir: &Path) -> Vec<PersistenceFinding> {
    let mut findings = Vec::new();
    if let Ok(entries) = fs::read_dir(startup_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let path_str = path.to_string_lossy().to_string();
            let suspicious = is_suspicious_persistence_target(&path_str);
            let reason = if suspicious {
                "Unsigned script or temp-path binary registered in startup directory".into()
            } else {
                "Standard startup item".into()
            };
            findings.push(PersistenceFinding {
                path,
                is_suspicious: suspicious,
                reason,
            });
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistence_detection() {
        assert!(is_suspicious_persistence_target("C:\\Users\\User\\AppData\\Local\\Temp\\update.exe"));
        assert!(is_suspicious_persistence_target("C:\\Startup\\launcher.vbs"));
        assert!(is_suspicious_persistence_target("powershell.exe -enc AAAA"));

        // Legitimate startup apps
        assert!(!is_suspicious_persistence_target("C:\\Program Files\\Slack\\Slack.exe"));
        assert!(!is_suspicious_persistence_target("C:\\Program Files\\Google\\Chrome\\chrome.exe"));
    }

    #[test]
    fn test_scan_startup_directory() {
        let temp_dir = std::env::temp_dir().join(format!("sentinel_persist_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let bad_file = temp_dir.join("updater.vbs");
        fs::write(&bad_file, b"Wscript.Echo 1").unwrap();

        let findings = scan_startup_directory(&temp_dir);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].is_suspicious);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
