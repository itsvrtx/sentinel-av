use std::env;
use std::io::{self, Write};
use std::path::Path;

fn main() {
    let target = env::args().nth(1).unwrap_or_else(|| ".".to_string());
    let vault = Path::new("quarantine_vault");

    println!("Sentinel AV Daemon — Starting scan on: {target}");
    let report = core_scanner::scan_directory_with_progress(
        Path::new(&target),
        Path::new("rules"),
        |count, path| {
            if count % 25 == 0 {
                print!("\rScanned {} files... (currently: {})", count, path.file_name().unwrap_or_default().to_string_lossy());
                io::stdout().flush().ok();
            }
        },
    )
    .expect("Scan failed");

    println!("\rScan complete. Checked {} file(s) in {} ms.", report.files_scanned, report.duration_ms);

    if report.findings.is_empty() {
        println!("Status: Clean. No threats found.");
        return;
    }

    println!("\n[!] Found {} threat(s):", report.findings.len());

    for item in report.findings {
        let rule = item.matched_rule.unwrap_or_else(|| "Unknown".into());
        println!("[ALERT] File: {}\n  SHA-256: {}\n  Matched Rule: {}", item.path, item.sha256, rule);

        match quarantine::quarantine_file(Path::new(&item.path), &item.sha256, &rule, vault) {
            Ok(entry) => {
                println!("  -> Moved to quarantine vault (ID: {})", entry.id);
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
