use quarantine::QuarantineEntry;
use std::path::Path;

const VAULT_DIR: &str = "quarantine_vault";

#[tauri::command]
fn scan_folder(target: String) -> Result<Vec<QuarantineEntry>, String> {
    let results = core_scanner::scan_directory(Path::new(&target));
    let vault = Path::new(VAULT_DIR);
    let mut newly_quarantined = Vec::new();

    for item in results {
        let rule = item.matched_rule.unwrap_or_else(|| "Unknown".into());
        let entry = quarantine::quarantine_file(Path::new(&item.path), &item.sha256, &rule, vault)
            .map_err(|e| e.to_string())?;
        newly_quarantined.push(entry);
    }

    Ok(newly_quarantined)
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
async fn pick_custom_folder() -> Option<String> {
    rfd::AsyncFileDialog::new()
        .set_title("Choose a folder to scan")
        .pick_folder()
        .await
        .map(|handle| handle.path().display().to_string())
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
            delete_item
        ])
        .run(tauri::generate_context!())
        .expect("error while running Sentinel AV");
}

#[derive(serde::Serialize)]
struct FolderOption {
    label: String,
    path: String,
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