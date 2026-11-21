use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const XOR_KEY: u8 = 0xAA;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub sha256: String,
    pub rule: String,
}

/// Copies a file in 64 KB chunks while applying an XOR mask to neutralize it.
fn stream_xor_copy(src: &Path, dst: &Path) -> io::Result<()> {
    let mut input = File::open(src)?;
    let mut output = File::create(dst)?;
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        for byte in &mut buffer[..n] {
            *byte ^= XOR_KEY;
        }
        output.write_all(&buffer[..n])?;
    }
    output.flush()
}

/// Moves a flagged file into the quarantine vault and writes its metadata.
pub fn quarantine_file(
    file_path: &Path,
    sha256: &str,
    rule: &str,
    vault_dir: &Path,
) -> io::Result<QuarantineEntry> {
    fs::create_dir_all(vault_dir)?;

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let hash_prefix = &sha256[..sha256.len().min(8)];
    let id = format!("{nanos}_{hash_prefix}");

    let quar_path = vault_dir.join(format!("{id}.quar"));
    let meta_path = vault_dir.join(format!("{id}.json"));

    stream_xor_copy(file_path, &quar_path)?;
    fs::remove_file(file_path)?;

    let entry = QuarantineEntry {
        id,
        original_path: file_path.display().to_string(),
        sha256: sha256.to_string(),
        rule: rule.to_string(),
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
    fs::remove_file(quar_path)?;
    fs::remove_file(meta_path)?;

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