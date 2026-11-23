use quarantine::QuarantineEntry;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use sysinfo::{Pid, System};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager, WindowEvent};
use tauri_plugin_notification::NotificationExt;

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
    files_skipped: usize,
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
    exe_path: String,
    cmd: String,
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

fn resolve_bundle_rules_dir(app: &tauri::AppHandle) -> PathBuf {
    if let Ok(res_dir) = app.path().resource_dir() {
        let p = res_dir.join("rules");
        if p.exists() {
            return p;
        }
    }
    for candidate in ["rules", "../../rules", "../rules"] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return p;
        }
    }
    PathBuf::from("rules")
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
async fn scan_folder(
    app: tauri::AppHandle,
    target: String,
    notify: Option<bool>,
) -> Result<ScanSummary, String> {
    let rules_dir = resolve_bundle_rules_dir(&app);
    let notify_clean = notify.unwrap_or(true);
    tauri::async_runtime::spawn_blocking(move || {
        let vault = get_vault_path();

        let report = core_scanner::scan_directory_with_progress(
            Path::new(&target),
            &rules_dir,
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
                        key: 0xAA,
                        key_hex: String::new(),
                    });
                }
            }
        }

        // Trigger Native Windows Notifications for Scan Events
        if !quarantined.is_empty() {
            let first_rule = quarantined.first().map(|q| q.rule.as_str()).unwrap_or("Malware");
            let body = format!(
                "{} threat(s) isolated in Quarantine Vault ({}). Open Sentinel AV immediately to review and delete or restore.",
                quarantined.len(),
                first_rule
            );
            if let Err(e) = app.notification()
                .builder()
                .title("Sentinel AV — Threat Detected!")
                .body(&body)
                .show()
            {
                eprintln!("Failed to fire threat notification: {e}");
            }
        } else if notify_clean {
            let body = format!(
                "Scanned {} file(s) in {} ms. No threats found.",
                report.files_scanned,
                report.duration_ms
            );
            if let Err(e) = app.notification()
                .builder()
                .title("Sentinel AV — Scan Complete")
                .body(&body)
                .show()
            {
                eprintln!("Failed to fire clean scan notification: {e}");
            }
        }

        Ok(ScanSummary {
            files_scanned: report.files_scanned,
            files_skipped: report.files_skipped,
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
fn restore_all_items() -> Result<usize, String> {
    let vault = get_vault_path();
    quarantine::restore_all(&vault).map_err(|e| e.to_string())
}

#[tauri::command]
fn clear_clean_logs() -> Result<usize, String> {
    let log_path = core_scanner::scan_log::get_default_log_path();
    core_scanner::scan_log::clear_clean_logs(&log_path).map_err(|e| e.to_string())
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
            let exe_path = proc.exe().map(|p| p.display().to_string()).unwrap_or_default();
            let cmd = proc.cmd().join(" ");
            ProcessInfo {
                pid: proc.pid().as_u32(),
                name: proc.name().to_string(),
                cpu_usage: proc.cpu_usage(),
                memory_mb: proc.memory() as f64 / 1024.0 / 1024.0,
                is_trojan,
                exe_path,
                cmd,
            }
        })
        .filter(|p| p.memory_mb > 1.0)
        .collect();

    *guard = Some(sys);

    Ok(processes)
}

#[tauri::command]
fn kill_process(pid: u32) -> Result<bool, String> {
    let mut guard = SYSTEM_MONITOR.lock().map_err(|e| e.to_string())?;
    let mut sys = guard.take().unwrap_or_else(System::new_all);
    sys.refresh_processes();
    let sys_killed = sys.process(Pid::from_u32(pid)).map(|proc| proc.kill()).unwrap_or(false);
    *guard = Some(sys);

    if sys_killed {
        return Ok(true);
    }

    // Fallback: On Windows, sysinfo TerminateProcess may fail without elevated rights, try taskkill
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        if let Ok(out) = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()
        {
            if out.status.success() {
                return Ok(true);
            }
        }
    }

    Err(format!(
        "Failed to terminate process {pid}. Administrator privilege may be required for system processes."
    ))
}

#[tauri::command]
fn open_file_location(path: String) -> Result<(), String> {
    let p = Path::new(&path);
    if !p.exists() {
        return Err(format!("File does not exist: {path}"));
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("explorer")
            .args(["/select,", &path])
            .creation_flags(0x08000000)
            .spawn()
            .map_err(|e| e.to_string())?;
    }

    #[cfg(not(target_os = "windows"))]
    {
        let parent = p.parent().unwrap_or(p);
        let _ = std::process::Command::new("xdg-open").arg(parent).spawn();
    }

    Ok(())
}

#[tauri::command]
fn get_scan_logs() -> Result<Vec<core_scanner::scan_log::ScanLogEntry>, String> {
    let log_path = core_scanner::scan_log::get_default_log_path();
    core_scanner::scan_log::read_recent_logs(&log_path, 20).map_err(|e| e.to_string())
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

#[cfg(target_os = "windows")]
fn register_app_user_model_id(app_id: &str, display_name: &str) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::process::CommandExt;

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn SetCurrentProcessExplicitAppUserModelID(AppID: *const u16) -> i32;
    }
    let wide_id: Vec<u16> = OsStr::new(app_id)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let _ = SetCurrentProcessExplicitAppUserModelID(wide_id.as_ptr());
    }

    let reg_key = format!(r"HKCU\Software\Classes\AppUserModelId\{app_id}");
    let _ = std::process::Command::new("reg")
        .args([
            "add",
            &reg_key,
            "/v",
            "DisplayName",
            "/t",
            "REG_SZ",
            "/d",
            display_name,
            "/f",
        ])
        .creation_flags(0x08000000)
        .output();

    if let Ok(exe_path) = std::env::current_exe() {
        let _ = std::process::Command::new("reg")
            .args([
                "add",
                &reg_key,
                "/v",
                "IconUri",
                "/t",
                "REG_SZ",
                "/d",
                &exe_path.display().to_string(),
                "/f",
            ])
            .creation_flags(0x08000000)
            .output();
    }
}

#[tauri::command]
fn toggle_fullscreen(window: tauri::Window) -> Result<bool, String> {
    let is_fullscreen = window.is_fullscreen().map_err(|e| e.to_string())?;
    let new_state = !is_fullscreen;
    window.set_fullscreen(new_state).map_err(|e| e.to_string())?;
    // Ensure always_on_top is never enabled so Alt+Tab and taskbar window switching remain functional
    let _ = window.set_always_on_top(false);
    Ok(new_state)
}

#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", &url])
            .creation_flags(0x08000000)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = std::process::Command::new("xdg-open")
            .arg(&url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn focus_and_open_vault(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
        let _ = window.emit("navigate-to-vault", ());
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            #[cfg(target_os = "windows")]
            register_app_user_model_id("com.itsvrtx.sentinelav", "Sentinel AV");

            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_min_size(Some(tauri::LogicalSize::new(920.0, 640.0)));
                let _ = window.set_always_on_top(false);
            }

            // System Tray menu items: Open Dashboard, Quick Scan, Quit
            let open_item = MenuItem::with_id(app, "open", "Open Dashboard", true, None::<&str>)?;
            let scan_item = MenuItem::with_id(app, "quick_scan", "Quick Scan", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open_item, &scan_item, &quit_item])?;

            let mut tray_builder = TrayIconBuilder::new()
                .menu(&menu)
                .show_menu_on_left_click(false)
                .tooltip("Sentinel AV")
                .on_menu_event(|app, event| {
                    match event.id.as_ref() {
                        "open" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.unminimize();
                                let _ = window.set_focus();
                            }
                        }
                        "quick_scan" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.unminimize();
                                let _ = window.set_focus();
                                let _ = window.emit("trigger-quick-scan", ());
                            }
                        }
                        "quit" => {
                            app.exit(0);
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                    }
                });

            if let Some(icon) = app.default_window_icon() {
                tray_builder = tray_builder.icon(icon.clone());
            }

            let _ = tray_builder.build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_common_folders,
            pick_custom_folder,
            scan_folder,
            get_quarantined,
            restore_item,
            restore_all_items,
            delete_item,
            get_system_processes,
            kill_process,
            open_file_location,
            get_scan_logs,
            clear_clean_logs,
            get_active_signatures,
            toggle_fullscreen,
            open_url,
            focus_and_open_vault
        ])
        .run(tauri::generate_context!())
        .expect("error while running Sentinel AV");
}
