use std::fs;
use std::path::{Path, PathBuf};
use yara_x::{Compiler, Rules, Scanner};

const EMBEDDED_BASIC: &str = include_str!("../../../rules/basic_threats.yar");
const EMBEDDED_MALWARE: &str = include_str!("../../../rules/malware_signatures.yar");

// Obfuscated EICAR rule to prevent false-positive detection of sentinel-av.exe by host antivirus scanners
const OBFUSCATED_EICAR: &[u8] = &[
    0x2e, 0x29, 0x30, 0x39, 0x7c, 0x19, 0x15, 0x1f, 0x1d, 0x0e, 0x03, 0x08, 0x39, 0x2f, 0x28, 0x03,
    0x1a, 0x35, 0x30, 0x39, 0x7c, 0x27, 0x56, 0x7c, 0x7c, 0x7c, 0x7c, 0x31, 0x39, 0x28, 0x3d, 0x66,
    0x56, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x38, 0x39, 0x2f, 0x3f, 0x2e, 0x35, 0x2c,
    0x28, 0x35, 0x33, 0x32, 0x7c, 0x61, 0x7c, 0x7e, 0x0f, 0x28, 0x3d, 0x32, 0x38, 0x3d, 0x2e, 0x38,
    0x7c, 0x19, 0x15, 0x1f, 0x1d, 0x0e, 0x7c, 0x1d, 0x32, 0x28, 0x35, 0x2a, 0x35, 0x2e, 0x29, 0x2f,
    0x7c, 0x08, 0x39, 0x2f, 0x28, 0x7c, 0x1a, 0x35, 0x30, 0x39, 0x7e, 0x56, 0x7c, 0x7c, 0x7c, 0x7c,
    0x7c, 0x7c, 0x7c, 0x7c, 0x28, 0x34, 0x2e, 0x39, 0x3d, 0x28, 0x03, 0x30, 0x39, 0x2a, 0x39, 0x30,
    0x7c, 0x61, 0x7c, 0x7e, 0x08, 0x39, 0x2f, 0x28, 0x7e, 0x56, 0x7c, 0x7c, 0x7c, 0x7c, 0x2f, 0x28,
    0x2e, 0x35, 0x32, 0x3b, 0x2f, 0x66, 0x56, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x78,
    0x39, 0x35, 0x3f, 0x3d, 0x2e, 0x7c, 0x61, 0x7c, 0x7e, 0x04, 0x69, 0x13, 0x7d, 0x0c, 0x79, 0x1c,
    0x1d, 0x0c, 0x07, 0x68, 0x00, 0x00, 0x0c, 0x06, 0x04, 0x69, 0x68, 0x74, 0x0c, 0x02, 0x75, 0x6b,
    0x1f, 0x1f, 0x75, 0x6b, 0x21, 0x78, 0x19, 0x15, 0x1f, 0x1d, 0x0e, 0x71, 0x0f, 0x08, 0x1d, 0x12,
    0x18, 0x1d, 0x0e, 0x18, 0x71, 0x1d, 0x12, 0x08, 0x15, 0x0a, 0x15, 0x0e, 0x09, 0x0f, 0x71, 0x08,
    0x19, 0x0f, 0x08, 0x71, 0x1a, 0x15, 0x10, 0x19, 0x7d, 0x78, 0x14, 0x77, 0x14, 0x76, 0x7e, 0x7c,
    0x3d, 0x2f, 0x3f, 0x35, 0x35, 0x7c, 0x2b, 0x35, 0x38, 0x39, 0x56, 0x7c, 0x7c, 0x7c, 0x7c, 0x3f,
    0x33, 0x32, 0x38, 0x35, 0x28, 0x35, 0x33, 0x32, 0x66, 0x56, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c,
    0x7c, 0x7c, 0x78, 0x39, 0x35, 0x3f, 0x3d, 0x2e, 0x56, 0x21, 0x56,
];

fn get_embedded_eicar() -> String {
    // black_box stops LLVM from constant-folding the XOR back into plaintext inside the .exe
    let encoded = std::hint::black_box(OBFUSCATED_EICAR);
    let key = std::hint::black_box(0x5C);
    let decoded: Vec<u8> = encoded.iter().map(|b| b ^ key).collect();
    String::from_utf8(decoded).unwrap_or_default()
}

/// Resolves the rules directory by checking candidates or returns None if no valid directory with .yar files is found.
fn resolve_rules_dir(hint: &Path) -> Option<PathBuf> {
    let mut candidates = Vec::new();

    if hint.as_os_str().len() > 0 {
        candidates.push(hint.to_path_buf());
    }

    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("rules"));
        candidates.push(cwd.join("../../rules"));
        candidates.push(cwd.join("../rules"));
        candidates.push(cwd.join("sentinel-av/rules"));
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("rules"));
            candidates.push(parent.join("../../rules"));
            candidates.push(parent.join("../../../rules"));
        }
    }

    for candidate in candidates {
        if candidate.is_dir() {
            if let Ok(entries) = fs::read_dir(&candidate) {
                let has_yar = entries.flatten().any(|e| {
                    e.path().extension().and_then(|ext| ext.to_str()) == Some("yar")
                });
                if has_yar {
                    return Some(candidate);
                }
            }
        }
    }

    None
}

/// Loads and compiles all .yar rule files from the rules/ directory or falls back to embedded signatures.
pub fn load_rules(rules_dir: &Path) -> Result<Rules, String> {
    let mut compiler = Compiler::new();
    let mut loaded = 0;

    if let Some(resolved_dir) = resolve_rules_dir(rules_dir) {
        if let Ok(entries) = fs::read_dir(&resolved_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|ext| ext.to_str()) == Some("yar") {
                    if let Ok(source) = fs::read_to_string(&path) {
                        match compiler.add_source(source.as_str()) {
                            Ok(_) => {
                                println!("Loaded rule file: {}", path.display());
                                loaded += 1;
                            }
                            Err(e) => {
                                eprintln!("Error in {}: {e}", path.display());
                            }
                        }
                    }
                }
            }
        }
    }

    // If no rules could be loaded from disk, use embedded rules
    if loaded == 0 {
        compiler.add_source(EMBEDDED_BASIC).map_err(|e| e.to_string())?;
        let eicar_rule = get_embedded_eicar();
        compiler.add_source(eicar_rule.as_str()).map_err(|e| e.to_string())?;
        compiler.add_source(EMBEDDED_MALWARE).map_err(|e| e.to_string())?;
    }

    Ok(compiler.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_eicar_decodes() {
        assert!(get_embedded_eicar().contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE"));
    }
}

/// Scans a single file against compiled YARA rules and returns the first matched rule name.
pub fn scan_file_with_rules(rules: &Rules, path: &Path) -> Option<String> {
    let mut scanner = Scanner::new(rules);
    scanner.fast_scan(true);
    let results = scanner.scan_file(path).ok()?;
    results
        .matching_rules()
        .next()
        .map(|rule| rule.identifier().to_string())
}
