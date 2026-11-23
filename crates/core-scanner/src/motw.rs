use std::path::Path;

/// Reads Windows NTFS `:Zone.Identifier` Alternate Data Stream (Mark of the Web).
pub fn get_zone_identifier(path: &Path) -> Option<u32> {
    #[cfg(target_os = "windows")]
    {
        use std::fs::File;
        use std::io::Read;

        let ads_path = format!("{}:Zone.Identifier", path.display());
        if let Ok(mut f) = File::open(&ads_path) {
            let mut content = String::new();
            if f.read_to_string(&mut content).is_ok() {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if let Some(val) = trimmed.strip_prefix("ZoneId=") {
                        return val.parse::<u32>().ok();
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    let _ = path;

    None
}

/// Checks if a file originated from the internet or untrusted zone (ZoneId >= 3).
pub fn is_mark_of_the_web(path: &Path) -> bool {
    get_zone_identifier(path).map(|z| z >= 3).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zone_identifier_missing_on_plain_file() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_plain_file.txt");
        let _ = std::fs::write(&test_file, b"sample text");

        assert_eq!(get_zone_identifier(&test_file), None);
        assert!(!is_mark_of_the_web(&test_file));

        let _ = std::fs::remove_file(test_file);
    }
}
