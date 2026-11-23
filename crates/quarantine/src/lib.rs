use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// shortcut: XOR masking for MVP isolation, upgrade to AES-256-GCM when key management service is integrated
pub fn get_xor_key() -> u8 {
    std::env::var("SENTINEL_XOR_KEY")
        .ok()
        .and_then(|s| {
            if let Some(stripped) = s.strip_prefix("0x") {
                u8::from_str_radix(stripped, 16).ok()
            } else {
                s.parse::<u8>().ok()
            }
        })
        .unwrap_or(0xAA)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub sha256: String,
    pub rule: String,
    #[serde(default)]
    pub file_size: u64,
    #[serde(default)]
    pub timestamp: u64,
}

/// Copies a file in 64 KB chunks while applying an XOR mask to neutralize it.
fn stream_xor_copy(src: &Path, dst: &Path) -> io::Result<u64> {
    let key = get_xor_key();
    let mut input = File::open(src)?;
    let mut output = File::create(dst)?;
    let mut buffer = [0u8; 64 * 1024];
    let mut total_bytes = 0u64;

    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        for byte in &mut buffer[..n] {
            *byte ^= key;
        }
        output.write_all(&buffer[..n])?;
        total_bytes += n as u64;
    }
    output.flush()?;
    Ok(total_bytes)
}

/// Moves a flagged file into the quarantine vault and writes its metadata.
pub fn quarantine_file(
    file_path: &Path,
    sha256: &str,
    rule: &str,
    vault_dir: &Path,
) -> io::Result<QuarantineEntry> {
    fs::create_dir_all(vault_dir)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = now.as_nanos();
    let secs = now.as_secs();
    let hash_prefix = &sha256[..sha256.len().min(8)];
    let id = format!("{nanos}_{hash_prefix}");

    let quar_path = vault_dir.join(format!("{id}.quar"));
    let meta_path = vault_dir.join(format!("{id}.json"));

    let file_size = stream_xor_copy(file_path, &quar_path)?;

    // Try removing original; if readonly, try clearing readonly bit first
    if let Err(e) = fs::remove_file(file_path) {
        if let Ok(metadata) = fs::metadata(file_path) {
            let mut permissions = metadata.permissions();
            if permissions.readonly() {
                permissions.set_readonly(false);
                let _ = fs::set_permissions(file_path, permissions);
                fs::remove_file(file_path)?;
            } else {
                return Err(e);
            }
        } else {
            return Err(e);
        }
    }

    let entry = QuarantineEntry {
        id,
        original_path: file_path.display().to_string(),
        sha256: sha256.to_string(),
        rule: rule.to_string(),
        file_size,
        timestamp: secs,
    };

    let json = serde_json::to_string_pretty(&entry)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    fs::write(meta_path, json)?;

    Ok(entry)
}

/// Lists all quarantined files so the UI can display them to the user.
pub fn list_quarantined(vault_dir: &Path) -> io::Result<Vec<QuarantineEntry>> {
    if !vault_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for item in fs::read_dir(vault_dir)? {
        let path = item?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            if let Ok(data) = fs::read_to_string(&path) {
                if let Ok(entry) = serde_json::from_str::<QuarantineEntry>(&data) {
                    entries.push(entry);
                }
            }
        }
    }
    // Newest first
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    Ok(entries)
}

/// Restores a quarantined file back to its original location (e.g., false positive).
pub fn restore_file(id: &str, vault_dir: &Path) -> io::Result<PathBuf> {
    let quar_path = vault_dir.join(format!("{id}.quar"));
    let meta_path = vault_dir.join(format!("{id}.json"));

    let data = fs::read_to_string(&meta_path)?;
    let entry: QuarantineEntry = serde_json::from_str(&data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let original = PathBuf::from(&entry.original_path);
    if let Some(parent) = original.parent() {
        fs::create_dir_all(parent)?;
    }

    // Applying the same XOR key restores the original bytes
    stream_xor_copy(&quar_path, &original)?;
    let _ = fs::remove_file(quar_path);
    let _ = fs::remove_file(meta_path);

    Ok(original)
}

/// Permanently deletes a quarantined file — call ONLY after user confirmation.
pub fn delete_permanently(id: &str, vault_dir: &Path) -> io::Result<()> {
    let quar_path = vault_dir.join(format!("{id}.quar"));
    let meta_path = vault_dir.join(format!("{id}.json"));

    if quar_path.exists() {
        fs::remove_file(quar_path)?;
    }
    if meta_path.exists() {
        fs::remove_file(meta_path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quarantine_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!("sentinel_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let sample_file = temp_dir.join("sample.txt");
        let vault_dir = temp_dir.join("vault");
        let content = b"This is a malware test payload 12345";
        fs::write(&sample_file, content).unwrap();

        // 1. Quarantine file
        let entry = quarantine_file(&sample_file, "fake_sha256", "Test_Rule", &vault_dir).unwrap();
        assert_eq!(entry.file_size, content.len() as u64);
        assert!(!sample_file.exists());

        // 2. List vault
        let items = list_quarantined(&vault_dir).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, entry.id);

        // 3. Restore file
        let restored = restore_file(&entry.id, &vault_dir).unwrap();
        assert!(restored.exists());
        let restored_bytes = fs::read(&restored).unwrap();
        assert_eq!(restored_bytes, content);

        // 4. Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
