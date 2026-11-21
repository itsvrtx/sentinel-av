use std::env;
use std::path::Path;

fn main() {
    let target = env::args().nth(1).unwrap_or_else(|| ".".to_string());
    println!("Scanning: {target}");

    let results = core_scanner::scan_directory(Path::new(&target));
    if results.is_empty() {
        println!("No threats found.");
    } else {
        for item in results {
            println!(
                "[ALERT] {} | Rule: {} | SHA-256: {}",
                item.path,
                item.matched_rule.unwrap_or_default(),
                item.sha256
            );
        }
    }
}