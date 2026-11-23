use std::env;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Real-Time Background Watch Mode (Phase 1 & 2 headless daemon)
    if args.len() >= 2 && (args[1] == "--watch" || args[1] == "-w") {
        let watch_path = args.get(2).map(|s| s.as_str()).unwrap_or(".");
        let watch_dir = PathBuf::from(watch_path);
        println!("Sentinel AV Daemon (Phase 1 & 2) — Active Real-Time File Defense initialized.");
        println!("Monitoring directory: {}", watch_dir.display());
        println!("Press Ctrl+C to terminate background daemon.");

        let mut sensor = kernel_sensor::DirectorySensor::new(watch_dir);
        let rules_dir = PathBuf::from("rules");

        sensor.start(Duration::from_millis(500), move |event| {
            println!("\n[EVENT {:?}] File: {}", event.kind, event.path.display());
            if event.path.is_file() {
                match core_scanner::scan_directory_with_progress(&event.path, &rules_dir, |_, _| {}) {
                    Ok(report) => {
                        for item in report.findings {
                            let rule = item.matched_rule.unwrap_or_else(|| "Unknown".into());
                            println!("[ALERT] Malicious file detected: {} (Rule: {})", item.path, rule);
                            let v = Path::new("quarantine_vault");
                            if let Ok(entry) = quarantine::quarantine_file(Path::new(&item.path), &item.sha256, &rule, v) {
                                println!("  -> Successfully neutralized into quarantine vault (ID: {})", entry.id);
                            }
                        }
                    }
                    Err(e) => eprintln!("Scan error: {e}"),
                }
            }
        });

        // Keep headless daemon running
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

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

    println!("\rScan complete. Checked {} file(s) ({} skipped) in {} ms.", report.files_scanned, report.files_skipped, report.duration_ms);

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
