use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Scans a file in 64 KB chunks for a known suspicious byte pattern.
pub fn find_signature(path: &Path, signature: &[u8]) -> io::Result<bool> {
    if signature.is_empty() {
        return Ok(false);
    }

    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; 64 * 1024 + signature.len()];
    let mut carry = 0;

    loop {
        let bytes_read = file.read(&mut buffer[carry..])?;
        if bytes_read == 0 {
            return Ok(false);
        }

        let total = carry + bytes_read;
        if buffer[..total].windows(signature.len()).any(|w| w == signature) {
            return Ok(true);
        }

        // Keep the tail bytes so a signature split across two chunks isn't missed
        carry = signature.len().saturating_sub(1).min(total);
        buffer.copy_within(total - carry..total, 0);
    }
}