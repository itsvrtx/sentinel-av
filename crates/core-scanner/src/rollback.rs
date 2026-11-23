use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const MAX_BUFFER_BYTES: usize = 16 * 1024 * 1024; // 16 MB capped ring buffer

#[derive(Debug, Clone)]
struct SnapshotEntry {
    data: Vec<u8>,
}

/// 16 MB Copy-on-Write micro-rollback ring buffer for ransomware defense.
pub struct MicroRollbackBuffer {
    snapshots: HashMap<PathBuf, SnapshotEntry>,
    current_bytes: usize,
}

impl Default for MicroRollbackBuffer {
    fn default() -> Self {
        Self {
            snapshots: HashMap::new(),
            current_bytes: 0,
        }
    }
}

impl MicroRollbackBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshots a file before it is touched by an untrusted write.
    pub fn backup_file(&mut self, path: &Path) -> io::Result<bool> {
        if self.snapshots.contains_key(path) {
            return Ok(true); // Already snapshotted
        }

        let metadata = fs::metadata(path)?;
        let file_len = metadata.len() as usize;

        // Skip files larger than the entire buffer limit
        if file_len > MAX_BUFFER_BYTES {
            return Ok(false);
        }

        // Evict oldest entries if capacity exceeded
        while self.current_bytes + file_len > MAX_BUFFER_BYTES && !self.snapshots.is_empty() {
            if let Some(oldest_key) = self.snapshots.keys().next().cloned() {
                if let Some(removed) = self.snapshots.remove(&oldest_key) {
                    self.current_bytes = self.current_bytes.saturating_sub(removed.data.len());
                }
            }
        }

        let mut file = File::open(path)?;
        let mut data = Vec::with_capacity(file_len);
        file.read_to_end(&mut data)?;

        self.current_bytes += data.len();
        self.snapshots.insert(path.to_path_buf(), SnapshotEntry { data });

        Ok(true)
    }

    /// Restores all snapshotted files to disk after a ransomware threat is terminated.
    pub fn rollback_all(&self) -> io::Result<usize> {
        let mut restored = 0;
        for (path, entry) in &self.snapshots {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let mut file = File::create(path)?;
            file.write_all(&entry.data)?;
            file.flush()?;
            restored += 1;
        }
        Ok(restored)
    }

    pub fn clear(&mut self) {
        self.snapshots.clear();
        self.current_bytes = 0;
    }

    pub fn count(&self) -> usize {
        self.snapshots.len()
    }

    pub fn current_size(&self) -> usize {
        self.current_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_micro_rollback_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!("sentinel_rollback_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let test_doc = temp_dir.join("financial_report.xlsx");
        let original_data = b"CONFIDENTIAL_FINANCIAL_SHEET_DATA_2026";
        fs::write(&test_doc, original_data).unwrap();

        let mut buffer = MicroRollbackBuffer::new();
        assert!(buffer.backup_file(&test_doc).unwrap());
        assert_eq!(buffer.count(), 1);

        // Simulate ransomware encrypting the file
        fs::write(&test_doc, b"ENCRYPTED_LOCKED_PAY_1_BITCOIN_TO_RECOVER").unwrap();
        assert_ne!(fs::read(&test_doc).unwrap(), original_data);

        // Trigger rollback
        let restored_count = buffer.rollback_all().unwrap();
        assert_eq!(restored_count, 1);
        assert_eq!(fs::read(&test_doc).unwrap(), original_data);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
