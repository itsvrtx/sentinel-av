use std::env;
use std::io::{self, Write};
use std::path::Path;

fn main() {
    let target = env::args().nth(1).unwrap_or_else(|| ".".to_string());
    let vault = Path::new("quarantine_vault");

    println!("Scanning: {target}");
    let results = core_scanner::scan_directory(Path::new(&target));

    if results.is_empty() {
        println!("No threats found.");
        return;
    }

    for item in results {
        let rule = item.matched_rule.unwrap_or_else(|| "Unknown".into());
        println!("[ALERT] {} | Rule: {}", item.path, rule);

        match quarantine::quarantine_file(Path::new(&item.path), &item.sha256, &rule, vault) {
            Ok(entry) => {
                println!("  -> Moved to quarantine (ID: {})", entry.id);
                print!("  -> Permanently delete this file? [y/N]: ");
                io::stdout().flush().ok();

                let mut answer = String::new();
                if io::stdin().read_line(&mut answer).is_ok()
                    && answer.trim().eq_ignore_ascii_case("y")
                {
                    let _ = quarantine::delete_permanently(&entry.id, vault);
                    println!("  -> Deleted permanently.");
                } else {
                    println!("  -> Kept safely in quarantine.");
                }
            }
            Err(e) => eprintln!("  -> Failed to quarantine: {e}"),
        }
    }
}