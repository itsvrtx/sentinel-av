use quarantine::QuarantineEntry;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use sysinfo::{Pid, System};
use tauri::Emitter;

#[derive(serde::Serialize)]
struct FolderOption {
    label: String,
    path: String,
}

#[derive(serde::Serialize, Clone)]
struct ScanProgress {
    count: usize,
    current_file: String,
}

#[derive(serde::Serialize)]
struct ScanSummary {
    files_scanned: usize,
    duration_ms: u128,
    quarantined: Vec<QuarantineEntry>,
}

#[derive(serde::Serialize)]
struct ProcessInfo {
    pid: u32,
    name: String,
    cpu_usage: f32,
    memory_mb: f64,
    is_trojan: bool,
}

#[derive(serde::Serialize)]
struct RuleSummary {
    name: String,
    category: String,
    description: String,
}

fn get_vault_path() -> PathBuf {
    if let Ok(dir) = std::env::var("SENTINEL_VAULT_DIR") {
        return PathBuf::from(dir);
    }
    if Path::new("quarantine_vault").exists() {
        return PathBuf::from("quarantine_vault");
    }
    if Path::new("../../quarantine_vault").exists() {
        return PathBuf::from("../../quarantine_vault");
    }
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        let p = PathBuf::from(local).join("SentinelAV").join("quarantine_vault");
        let _ = std::fs::create_dir_all(&p);
        return p;
    }
    if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        let p = PathBuf::from(home).join(".sentinel-av").join("quarantine_vault");
        let _ = std::fs::create_dir_all(&p);
        return p;
    }
    PathBuf::from("quarantine_vault")
}

#[tauri::command]
fn get_common_folders() -> Vec<FolderOption> {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());

    let sep = std::path::MAIN_SEPARATOR;
    let mut folders = vec![
        FolderOption { label: "Downloads".into(), path: format!("{home}{sep}Downloads") },
        FolderOption { label: "Desktop".into(), path: format!("{home}{sep}Desktop") },
        FolderOption { label: "Documents".into(), path: format!("{home}{sep}Documents") },
        FolderOption { label: "User Home".into(), path: home },
    ];

    // Detect test_lab if present
    for candidate in ["test_lab", "../../test_lab", "../test_lab"] {
        let p = Path::new(candidate);
        if p.exists() {
            if let Ok(abs) = std::fs::canonicalize(p) {
                let clean_path = abs.display().to_string();
                let clean_path = clean_path.trim_start_matches(r"\\?\").to_string();
                folders.push(FolderOption {
                    label: "Test Lab (Demo)".into(),
                    path: clean_path,
                });
                break;
            }
        }
    }

    folders
}

#[tauri::command]
async fn pick_custom_folder() -> Option<String> {
    rfd::AsyncFileDialog::new()
        .set_title("Choose a folder to scan")
        .pick_folder()
        .await
        .map(|handle| handle.path().display().to_string())
}

#[tauri::command]
async fn scan_folder(app: tauri::AppHandle, target: String) -> Result<ScanSummary, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let rules_dir = Path::new("rules");
        let vault = get_vault_path();

        let report = core_scanner::scan_directory_with_progress(
            Path::new(&target),
            rules_dir,
            |count, path| {
                let _ = app.emit(
                    "scan-progress",
                    ScanProgress {
                        count,
                        current_file: path.display().to_string(),
                    },
                );
            },
        )?;

        let mut quarantined = Vec::new();
        for item in report.findings {
            let rule = item.matched_rule.unwrap_or_else(|| "Unknown".into());
            match quarantine::quarantine_file(Path::new(&item.path), &item.sha256, &rule, &vault) {
                Ok(entry) => quarantined.push(entry),
                Err(e) => {
                    eprintln!("Failed to quarantine {}: {e}", item.path);
                    quarantined.push(QuarantineEntry {
                        id: format!("failed_{}", quarantined.len()),
                        original_path: item.path,
                        sha256: item.sha256,
                        rule: format!("{rule} (Quarantine warning: {e})"),
                        file_size: 0,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    });
                }
            }
        }

        Ok(ScanSummary {
            files_scanned: report.files_scanned,
            duration_ms: report.duration_ms,
            quarantined,
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn get_quarantined() -> Result<Vec<QuarantineEntry>, String> {
    let vault = get_vault_path();
    quarantine::list_quarantined(&vault).map_err(|e| e.to_string())
}

#[tauri::command]
fn restore_item(id: String) -> Result<String, String> {
    let vault = get_vault_path();
    let restored = quarantine::restore_file(&id, &vault).map_err(|e| e.to_string())?;
    Ok(restored.display().to_string())
}

#[tauri::command]
fn delete_item(id: String) -> Result<(), String> {
    let vault = get_vault_path();
    quarantine::delete_permanently(&id, &vault).map_err(|e| e.to_string())
}

// Global system monitor cache for accurate delta CPU measurement
static SYSTEM_MONITOR: Mutex<Option<System>> = Mutex::new(None);

#[tauri::command]
fn get_system_processes() -> Result<Vec<ProcessInfo>, String> {
    let mut guard = SYSTEM_MONITOR.lock().map_err(|e| e.to_string())?;
    
    let mut sys = if let Some(sys) = guard.take() {
        sys
    } else {
        let mut s = System::new_all();
        s.refresh_processes();
        std::thread::sleep(Duration::from_millis(150));
        s
    };

    sys.refresh_processes();

    let trojan_keywords = [
        "trojan", "malware", "virus", "ransomware", "spyware",
        "keylogger", "rootkit", "backdoor", "botnet", "miner",
        "cryptojack", "mimikatz", "payload"
    ];

    let processes: Vec<ProcessInfo> = sys.processes().values()
        .map(|proc| {
            let name_lower = proc.name().to_lowercase();
            let is_trojan = trojan_keywords.iter().any(|kw| name_lower.contains(kw));
            ProcessInfo {
                pid: proc.pid().as_u32(),
                name: proc.name().to_string(),
                cpu_usage: proc.cpu_usage(),
                memory_mb: proc.memory() as f64 / 1024.0 / 1024.0,
                is_trojan,
            }
        })
        .filter(|p| p.memory_mb > 1.0)
        .collect();

    *guard = Some(sys);

    Ok(processes)
}

#[tauri::command]
fn kill_process(pid: u32) -> Result<bool, String> {
    let mut sys = System::new_all();
    sys.refresh_processes();
    if let Some(proc) = sys.process(Pid::from_u32(pid)) {
        Ok(proc.kill())
    } else {
        Err(format!("Process with PID {pid} not found."))
    }
}

#[tauri::command]
fn get_active_signatures() -> Vec<RuleSummary> {
    vec![
        RuleSummary {
            name: "EICAR_Test_File".into(),
            category: "Standard Test".into(),
            description: "Industry-standard antivirus verification signature".into(),
        },
        RuleSummary {
            name: "Test_Suspicious_Pattern".into(),
            category: "Test Pattern".into(),
            description: "Internal Sentinel AV test verification signature".into(),
        },
        RuleSummary {
            name: "Trojan_Generic_Dropper".into(),
            category: "Trojan / Dropper".into(),
            description: "Detects memory injection, staging downloaders, and concealed execution".into(),
        },
        RuleSummary {
            name: "Trojan_RAT_Indicator".into(),
            category: "Trojan / RAT".into(),
            description: "Detects Remote Access Trojans (AsyncRAT, NjRAT, Remcos, Quasar)".into(),
        },
        RuleSummary {
            name: "Trojan_InfoStealer_Vault".into(),
            category: "Trojan / Stealer".into(),
            description: "Detects browser credential, cookie, and cryptocurrency wallet harvesting".into(),
        },
        RuleSummary {
            name: "Suspicious_Webshell".into(),
            category: "Webshell / Backdoor".into(),
            description: "Detects common PHP webshells (c99, r57, b374k, eval base64)".into(),
        },
        RuleSummary {
            name: "Suspicious_PowerShell_Downloader".into(),
            category: "Malicious Script".into(),
            description: "Detects encoded PowerShell cradles, certutil, bitsadmin downloads".into(),
        },
        RuleSummary {
            name: "Ransomware_Extortion_Note".into(),
            category: "Ransomware".into(),
            description: "Detects ransomware encryption notes and payment demands".into(),
        },
        RuleSummary {
            name: "Suspicious_Reverse_Shell".into(),
            category: "Command & Control".into(),
            description: "Detects interactive netcat, bash, and python reverse shell pipes".into(),
        },
    ]
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_common_folders,
            pick_custom_folder,
            scan_folder,
            get_quarantined,
            restore_item,
            delete_item,
            get_system_processes,
            kill_process,
            get_active_signatures
        ])
        .run(tauri::generate_context!())
        .expect("error while running Sentinel AV");
}
