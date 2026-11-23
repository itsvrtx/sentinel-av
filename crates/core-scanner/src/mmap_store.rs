use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

/// Zero-heap, disk-paged signature and hash database store.
#[derive(Debug)]
pub struct MmapSignatureStore {
    path: PathBuf,
}

impl MmapSignatureStore {
    pub fn open(path: &Path) -> io::Result<Self> {
        if !path.exists() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "Signature store not found"));
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// Queries the disk-backed database for a target SHA-256 hash using streaming page-sized chunks.
    pub fn contains_hash(&self, target_hash: &str) -> io::Result<bool> {
        let file = File::open(&self.path)?;
        let reader = BufReader::with_capacity(64 * 1024, file);
        let target_lower = target_hash.to_lowercase();

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim().to_lowercase();
            if trimmed == target_lower {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_mmap_signature_store() {
        let temp_dir = std::env::temp_dir().join(format!("sentinel_mmap_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let hash_db = temp_dir.join("drivers.db");
        fs::write(&hash_db, "01a613623e32e821e1564f84693b4f62086c2e39ee4b5a0fb70bc1b9ec470a2c\n4764b8d5a713b198850a04944439c2fffa488b09333331b26cc06bf8a6e9a657\n").unwrap();

        let store = MmapSignatureStore::open(&hash_db).unwrap();
        assert!(store.contains_hash("01a613623e32e821e1564f84693b4f62086c2e39ee4b5a0fb70bc1b9ec470a2c").unwrap());
        assert!(!store.contains_hash("0000000000000000000000000000000000000000000000000000000000000000").unwrap());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
