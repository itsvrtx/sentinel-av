use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct HeaderEntropyAnalysis {
    pub entropy: f64,
    pub is_pe: bool,
    pub is_elf: bool,
    pub is_suspicious_packed: bool,
}

/// Inspects file headers (PE/ELF) and computes streaming Shannon entropy.
pub fn analyze_file_header_entropy(path: &Path) -> io::Result<HeaderEntropyAnalysis> {
    let mut file = File::open(path)?;
    let mut counts = [0u64; 256];
    let mut total_bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];

    // Read initial 1KB for header inspection
    let mut header = [0u8; 1024];
    let header_len = file.read(&mut header)?;

    // Check PE / ELF signatures
    let is_elf = header_len >= 4 && &header[0..4] == b"\x7fELF";
    let mut is_pe = false;
    if header_len >= 64 && &header[0..2] == b"MZ" {
        let e_lfanew = u32::from_le_bytes([header[0x3C], header[0x3D], header[0x3E], header[0x3F]]) as usize;
        if e_lfanew + 4 <= header_len {
            is_pe = &header[e_lfanew..e_lfanew + 4] == b"PE\0\0";
        } else if let Ok(_) = file.seek(SeekFrom::Start(e_lfanew as u64)) {
            let mut pe_sig = [0u8; 4];
            if file.read_exact(&mut pe_sig).is_ok() {
                is_pe = &pe_sig == b"PE\0\0";
            }
        }
    }

    // Reset and compute full streaming Shannon entropy in 64KB chunks
    file.seek(SeekFrom::Start(0))?;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        for &byte in &buffer[..n] {
            counts[byte as usize] += 1;
        }
        total_bytes += n as u64;
    }

    let entropy = if total_bytes == 0 {
        0.0
    } else {
        let total_f = total_bytes as f64;
        let mut h = 0.0;
        for &c in &counts {
            if c > 0 {
                let p = c as f64 / total_f;
                h -= p * p.log2();
            }
        }
        h
    };

    // shortcut: entropy threshold 7.2 flags UPX/Themida/ransomware packing, upgrade to ML model later
    let is_suspicious_packed = (is_pe || is_elf) && entropy > 7.2;

    Ok(HeaderEntropyAnalysis {
        entropy,
        is_pe,
        is_elf,
        is_suspicious_packed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_entropy_computation() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_entropy_plain.txt");
        let mut f = File::create(&test_file).unwrap();
        // Low entropy text file (repeating pattern)
        f.write_all(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        drop(f);

        let analysis = analyze_file_header_entropy(&test_file).unwrap();
        assert_eq!(analysis.entropy, 0.0);
        assert!(!analysis.is_pe);
        assert!(!analysis.is_suspicious_packed);

        let _ = std::fs::remove_file(test_file);
    }
}
