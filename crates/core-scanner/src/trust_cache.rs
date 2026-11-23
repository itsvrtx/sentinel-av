use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEntry {
    pub mtime_secs: u64,
    pub size: u64,
    pub sha256: String,
    pub is_clean: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TrustCache {
    pub entries: HashMap<String, TrustEntry>,
}

impl TrustCache {
    /// Loads the trust cache from disk; returns an empty cache if missing or corrupt.
    pub fn load_from_path(path: &Path) -> Self {
        if path.exists() {
            if let Ok(data) = fs::read_to_string(path) {
                if let Ok(cache) = serde_json::from_str::<TrustCache>(&data) {
                    return cache;
                }
            }
        }
        Self::default()
    }

    /// Persists the trust cache to disk.
    pub fn save_to_path(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string(self)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        fs::write(path, json)
    }

    /// Checks if a file with matching path, modification time, and size is known clean.
    pub fn is_trusted(&self, file_path: &Path, mtime_secs: u64, size: u64) -> bool {
        let key = file_path.to_string_lossy().to_string();
        if let Some(entry) = self.entries.get(&key) {
            entry.is_clean && entry.mtime_secs == mtime_secs && entry.size == size
        } else {
            false
        }
    }

    /// Inserts or updates a file's trust status.
    pub fn insert(
        &mut self,
        file_path: &Path,
        mtime_secs: u64,
        size: u64,
        sha256: String,
        is_clean: bool,
    ) {
        let key = file_path.to_string_lossy().to_string();
        self.entries.insert(
            key,
            TrustEntry {
                mtime_secs,
                size,
                sha256,
                is_clean,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_cache_lifecycle() {
        let mut cache = TrustCache::default();
        let path = Path::new("C:/test/file.exe");
        assert!(!cache.is_trusted(path, 100, 500));

        cache.insert(path, 100, 500, "abc123hash".into(), true);
        assert!(cache.is_trusted(path, 100, 500));

        // Modified mtime or size invalidates trust
        assert!(!cache.is_trusted(path, 101, 500));
        assert!(!cache.is_trusted(path, 100, 501));
    }
}
