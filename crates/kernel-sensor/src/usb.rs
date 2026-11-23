use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbThreat {
    pub path: PathBuf,
    pub description: String,
}

/// Inspects the root of a mounted USB or removable volume for autorun worms and suspicious shortcuts.
pub fn scan_removable_volume_root(drive_root: &Path) -> Vec<UsbThreat> {
    let mut threats = Vec::new();

    let autorun_path = drive_root.join("autorun.inf");
    if autorun_path.exists() {
        threats.push(UsbThreat {
            path: autorun_path,
            description: "Suspicious autorun.inf configuration file detected on removable drive".into(),
        });
    }

    if let Ok(entries) = fs::read_dir(drive_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let ext_lower = ext.to_lowercase();
                // Flag root-level LNK shortcuts or hidden EXE files common in USB worm spreading
                if ext_lower == "lnk" {
                    threats.push(UsbThreat {
                        path: path.clone(),
                        description: "Root-level LNK shortcut detected on removable media (common worm vector)".into(),
                    });
                } else if ext_lower == "exe" || ext_lower == "scr" || ext_lower == "vbs" {
                    if let Ok(metadata) = fs::metadata(&path) {
                        #[cfg(target_os = "windows")]
                        {
                            use std::os::windows::fs::MetadataExt;
                            const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
                            if (metadata.file_attributes() & FILE_ATTRIBUTE_HIDDEN) != 0 {
                                threats.push(UsbThreat {
                                    path,
                                    description: "Hidden executable file detected in root of removable media".into(),
                                });
                            }
                        }
                        #[cfg(not(target_os = "windows"))]
                        let _ = metadata;
                    }
                }
            }
        }
    }

    threats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usb_autorun_detection() {
        let temp_dir = std::env::temp_dir().join(format!("sentinel_usb_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let autorun = temp_dir.join("autorun.inf");
        fs::write(&autorun, b"[autorun]\nopen=malware.exe").unwrap();

        let threats = scan_removable_volume_root(&temp_dir);
        assert_eq!(threats.len(), 1);
        assert!(threats[0].description.contains("autorun.inf"));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
