use std::fs;
use std::path::Path;
use yara_x::{Compiler, Rules, Scanner};

/// Loads and compiles all .yar rule files from the rules/ directory.
pub fn load_rules(rules_dir: &Path) -> Result<Rules, String> {
    let mut compiler = Compiler::new();
    let entries = fs::read_dir(rules_dir).map_err(|e| format!("Cannot read rules dir: {e}"))?;

    let mut loaded = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("yar") {
            let source = fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
            compiler
                .add_source(source.as_str())
                .map_err(|e| format!("Invalid YARA rule in {}: {e}", path.display()))?;
            loaded += 1;
        }
    }

    if loaded == 0 {
        return Err(format!("No .yar files found in {}", rules_dir.display()));
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