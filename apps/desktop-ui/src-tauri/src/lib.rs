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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            scan_folder,
            get_quarantined,
            restore_item,
            delete_item
        ])
        .run(tauri::generate_context!())
        .expect("error while running Sentinel AV");
}