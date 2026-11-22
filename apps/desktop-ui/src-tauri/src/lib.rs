use quarantine::QuarantineEntry;
use std::path::Path;
use sysinfo::System;
use tauri::Emitter;

const VAULT_DIR: &str = "quarantine_vault";

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

#[tauri::command]
fn get_common_folders() -> Vec<FolderOption> {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());

    let sep = std::path::MAIN_SEPARATOR;
    vec![
        FolderOption { label: "Downloads".into(), path: format!("{home}{sep}Downloads") },
        FolderOption { label: "Desktop".into(), path: format!("{home}{sep}Desktop") },
        FolderOption { label: "Documents".into(), path: format!("{home}{sep}Documents") },
        FolderOption { label: "Full User Folder".into(), path: home },
    ]
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
        let rules_dir = if Path::new("rules").exists() {
            Path::new("rules")
        } else {
            Path::new("../../rules")
        };

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

        let vault = Path::new(VAULT_DIR);
        let mut quarantined = Vec::new();
        for item in report.findings {
            let rule = item.matched_rule.unwrap_or_else(|| "Unknown".into());
            let entry =
                quarantine::quarantine_file(Path::new(&item.path), &item.sha256, &rule, vault)
                    .map_err(|e| e.to_string())?;
            quarantined.push(entry);
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
    quarantine::list_quarantined(Path::new(VAULT_DIR)).map_err(|e| e.to_string())
}

#[tauri::command]
fn restore_item(id: String) -> Result<String, String> {
    let restored = quarantine::restore_file(&id, Path::new(VAULT_DIR)).map_err(|e| e.to_string())?;
    Ok(restored.display().to_string())
}

#[tauri::command]
fn delete_item(id: String) -> Result<(), String> {
    quarantine::delete_permanently(&id, Path::new(VAULT_DIR)).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_system_processes() -> Result<Vec<ProcessInfo>, String> {
    let mut sys = System::new_all();
    sys.refresh_processes();

    let trojan_keywords = ["trojan", "malware", "virus", "ransomware", "spyware", "keylogger", "rootkit", "backdoor", "botnet", "miner", "cryptojack"];

    let processes: Vec<ProcessInfo> = sys.processes().values()
        .map(|proc| {
            let name = proc.name().to_lowercase();
            let is_trojan = trojan_keywords.iter().any(|kw| name.contains(kw));
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

    Ok(processes)
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
            get_system_processes
        ])
        .run(tauri::generate_context!())
        .expect("error while running Sentinel AV");
}