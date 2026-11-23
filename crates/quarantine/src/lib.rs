use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAGIC_HEADER: &[u8; 4] = b"SQV1";
pub const CHUNK_SIZE: usize = 64 * 1024; // 64 KB chunked streaming

fn default_key() -> u8 {
    0xAA
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
    #[serde(default = "default_key")]
    pub key: u8,
    #[serde(default)]
    pub key_hex: String,
}

/// Encrypts a file in 64 KB chunks using AES-256-GCM with a unique nonce per chunk.
fn stream_aes_gcm_encrypt(src: &Path, dst: &Path, key_bytes: &[u8; 32]) -> io::Result<u64> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));
    let mut input = File::open(src)?;
    let mut output = File::create(dst)?;
    output.write_all(MAGIC_HEADER)?;

    let mut buffer = [0u8; CHUNK_SIZE];
    let mut total_plain_bytes = 0u64;

    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, &buffer[..n])
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("AES-GCM encryption failed: {e}")))?;

        let frame_len = (ciphertext.len() as u32).to_le_bytes();
        output.write_all(&frame_len)?;
        output.write_all(nonce.as_slice())?;
        output.write_all(&ciphertext)?;
        total_plain_bytes += n as u64;
    }

    output.flush()?;
    Ok(total_plain_bytes)
}

/// Decrypts and authenticates a framed AES-256-GCM quarantined file in 64 KB chunks.
fn stream_aes_gcm_decrypt(src: &Path, dst: &Path, key_bytes: &[u8; 32]) -> io::Result<u64> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));
    let mut input = File::open(src)?;
    let mut magic = [0u8; 4];
    input.read_exact(&mut magic)?;
    if &magic != MAGIC_HEADER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid quarantine file header (expected SQV1)",
        ));
    }

    let mut output = File::create(dst)?;
    let mut total_plain_bytes = 0u64;

    loop {
        let mut len_bytes = [0u8; 4];
        match input.read_exact(&mut len_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }

        let frame_len = u32::from_le_bytes(len_bytes) as usize;
        if frame_len > 128 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Corrupted quarantine frame length",
            ));
        }

        let mut nonce_bytes = [0u8; 12];
        input.read_exact(&mut nonce_bytes)?;
        let mut ciphertext = vec![0u8; frame_len];
        input.read_exact(&mut ciphertext)?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "AES-GCM authentication failed - file may be tampered",
                )
            })?;

        output.write_all(&plaintext)?;
        total_plain_bytes += plaintext.len() as u64;
    }

    output.flush()?;
    Ok(total_plain_bytes)
}

/// Legacy fallback: copies a file while applying single-byte XOR mask.
fn stream_xor_copy(src: &Path, dst: &Path, key: u8) -> io::Result<u64> {
    let mut input = File::open(src)?;
    let mut output = File::create(dst)?;
    let mut buffer = [0u8; CHUNK_SIZE];
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

/// Moves a flagged file into the quarantine vault and encrypts it with AES-256-GCM.
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

    // Generate fresh 256-bit random key per quarantined file
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let mut key_bytes: [u8; 32] = key.into();
    let key_hex = hex::encode(&key_bytes);

    let file_size = stream_aes_gcm_encrypt(file_path, &quar_path, &key_bytes)?;
    key_bytes.fill(0);

    // Try removing original; if readonly, clear readonly bit first
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
        key: default_key(),
        key_hex,
    };

    let json = serde_json::to_string_pretty(&entry)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    fs::write(&meta_path, json)?;
    restrict_vault_permissions(vault_dir, &quar_path, &meta_path);

    // The key lives only in the .json metadata; never hand it to the UI.
    Ok(QuarantineEntry { key_hex: String::new(), ..entry })
}

/// Locks down the vault on Unix; Windows DACLs are not set here.
/// shortcut: vault ACL hardening is Unix-only, add Windows DACLs via icacls when shipping to multi-user machines.
fn restrict_vault_permissions(vault_dir: &Path, quar_path: &Path, meta_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(vault_dir, fs::Permissions::from_mode(0o700));
        let _ = fs::set_permissions(quar_path, fs::Permissions::from_mode(0o600));
        let _ = fs::set_permissions(meta_path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = (vault_dir, quar_path, meta_path);
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
                if let Ok(mut entry) = serde_json::from_str::<QuarantineEntry>(&data) {
                    entry.key_hex.clear();
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

    let res = if !entry.key_hex.is_empty() {
        if let Ok(key_bytes) = hex::decode(&entry.key_hex) {
            if key_bytes.len() == 32 {
                let mut k = [0u8; 32];
                k.copy_from_slice(&key_bytes);
                stream_aes_gcm_decrypt(&quar_path, &original, &k)
            } else {
                stream_xor_copy(&quar_path, &original, entry.key)
            }
        } else {
            stream_xor_copy(&quar_path, &original, entry.key)
        }
    } else {
        // Fallback for older XOR-encrypted files
        stream_xor_copy(&quar_path, &original, entry.key)
    };

    match res {
        Ok(_) => {
            let _ = fs::remove_file(quar_path);
            let _ = fs::remove_file(meta_path);
            Ok(original)
        }
        Err(e) => {
            // Delete incomplete or corrupt restored file
            if original.exists() {
                let _ = fs::remove_file(&original);
            }
            Err(e)
        }
    }
}

/// Restores all files in the quarantine vault back to their original locations.
pub fn restore_all(vault_dir: &Path) -> io::Result<usize> {
    let items = list_quarantined(vault_dir)?;
    let mut restored_count = 0;
    for item in items {
        if restore_file(&item.id, vault_dir).is_ok() {
            restored_count += 1;
        }
    }
    Ok(restored_count)
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
    fn test_quarantine_and_restore_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("sentinel_aes_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let sample_file = temp_dir.join("sample.txt");
        let vault_dir = temp_dir.join("vault");
        let content = b"This is a high-security malware test payload 1234567890 with AES-GCM!";
        fs::write(&sample_file, content).unwrap();

        // 1. Quarantine file with AES-256-GCM
        let entry = quarantine_file(&sample_file, "fake_sha256", "Test_Rule", &vault_dir).unwrap();
        assert_eq!(entry.file_size, content.len() as u64);
        assert!(!sample_file.exists());
        assert!(entry.key_hex.is_empty(), "key must not be returned to callers");

        // 2. Verify header and encrypted bytes differ from plaintext
        let quar_file = vault_dir.join(format!("{}.quar", entry.id));
        let quar_bytes = fs::read(&quar_file).unwrap();
        assert!(quar_bytes.starts_with(MAGIC_HEADER));
        assert_ne!(&quar_bytes[4..], content);

        // 3. List vault
        let items = list_quarantined(&vault_dir).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, entry.id);
        assert!(items[0].key_hex.is_empty(), "key must not be listed to the UI");

        // 4. Restore file and verify exact byte match
        let restored = restore_file(&entry.id, &vault_dir).unwrap();
        assert!(restored.exists());
        let restored_bytes = fs::read(&restored).unwrap();
        assert_eq!(restored_bytes, content);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_tampered_quarantine_fails_auth() {
        let temp_dir = std::env::temp_dir().join(format!("sentinel_tamper_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let sample_file = temp_dir.join("tamper.bin");
        let vault_dir = temp_dir.join("vault");
        let content = b"Crucial system binary data to protect from tampering";
        fs::write(&sample_file, content).unwrap();

        let entry = quarantine_file(&sample_file, "fake_sha256", "Test_Rule", &vault_dir).unwrap();
        let quar_file = vault_dir.join(format!("{}.quar", entry.id));

        // Tamper with one byte in the ciphertext
        let mut quar_bytes = fs::read(&quar_file).unwrap();
        let last_idx = quar_bytes.len() - 1;
        quar_bytes[last_idx] ^= 0xFF;
        fs::write(&quar_file, &quar_bytes).unwrap();

        // Attempt restore - MUST fail authentication
        let res = restore_file(&entry.id, &vault_dir);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(!sample_file.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_delete_permanently() {
        let temp_dir = std::env::temp_dir().join(format!("sentinel_del_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let sample_file = temp_dir.join("to_delete.txt");
        let vault_dir = temp_dir.join("vault");
        fs::write(&sample_file, b"Temporary malicious content").unwrap();

        let entry = quarantine_file(&sample_file, "sha123", "Test_Rule", &vault_dir).unwrap();
        let quar_path = vault_dir.join(format!("{}.quar", entry.id));
        let meta_path = vault_dir.join(format!("{}.json", entry.id));
        assert!(quar_path.exists());
        assert!(meta_path.exists());

        delete_permanently(&entry.id, &vault_dir).unwrap();
        assert!(!quar_path.exists());
        assert!(!meta_path.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
