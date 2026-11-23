use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Exclusions {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub hashes: Vec<String>,
}

impl Exclusions {
    pub fn load_from_path(path: &Path) -> Self {
        if path.exists() {
            if let Ok(data) = fs::read_to_string(path) {
                if let Ok(ex) = serde_json::from_str::<Exclusions>(&data) {
                    return ex;
                }
            }
        }
        Self::default()
    }

    pub fn save_to_path(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        fs::write(path, json)
    }

    pub fn is_excluded(&self, path: &Path, sha256: Option<&str>) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();

        // 1. Path prefix or exact match
        for p in &self.paths {
            let p_lower = p.to_lowercase();
            if path_str == p_lower || path_str.starts_with(&p_lower) {
                return true;
            }
        }

        // 2. Extension check
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let ext_lower = ext.to_lowercase();
            for e in &self.extensions {
                if ext_lower == e.trim_start_matches('.').to_lowercase() {
                    return true;
                }
            }
        }

        // 3. Hash check
        if let Some(h) = sha256 {
            let h_lower = h.to_lowercase();
            for hash in &self.hashes {
                if h_lower == hash.to_lowercase() {
                    return true;
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exclusions() {
        let mut ex = Exclusions::default();
        ex.paths.push("C:/safe_folder".into());
        ex.extensions.push("tmp".into());
        ex.hashes.push("deadbeef".into());

        assert!(ex.is_excluded(Path::new("C:/safe_folder/sub/file.exe"), None));
        assert!(ex.is_excluded(Path::new("D:/other/file.tmp"), None));
        assert!(ex.is_excluded(Path::new("D:/other/test.bin"), Some("deadbeef")));
        assert!(!ex.is_excluded(Path::new("D:/other/virus.exe"), Some("badcafe")));
    }
}
