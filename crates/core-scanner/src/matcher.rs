use std::fs;
use std::path::{Path, PathBuf};
use yara_x::{Compiler, Rules, Scanner};

const EMBEDDED_BASIC: &str = include_str!("../../../rules/basic_threats.yar");
const EMBEDDED_EICAR: &str = include_str!("../../../rules/eicar.yar");
const EMBEDDED_MALWARE: &str = include_str!("../../../rules/malware_signatures.yar");

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
        compiler.add_source(EMBEDDED_EICAR).map_err(|e| e.to_string())?;
        compiler.add_source(EMBEDDED_MALWARE).map_err(|e| e.to_string())?;
    }

    Ok(compiler.build())
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
