# Sentinel AV — Project Context (`CLAUDE.md`)

## Overview
**Sentinel AV** is a free, open-source, low-RAM antivirus application built in **Rust** with a **[Tauri 2](https://v2.tauri.app/)** desktop UI.

### Core Design Principles
- **Low RAM footprint:** Files are hashed and scanned in streaming 64 KB chunks (`BufReader`) or memory-mapped via [YARA-X](https://crates.io/crates/yara-x) rather than loading entire files into memory.
- **User-approved deletion only:** Flagged files are never deleted silently. They are moved to a locked `quarantine_vault/` first so the user can review the threat details and choose **Restore (Safe)** or **Delete Permanently**.
- **3-layer architecture:**
  1. `crates/kernel-sensor` — Lightweight kernel hook (Windows File System Minifilter / Linux eBPF LSM) that watches file opens/executions and forwards paths.
  2. `crates/core-scanner` & `crates/service-daemon` — User-space scanning engine (SHA-256 + YARA-X pattern matching + quarantine).
  3. `apps/desktop-ui` — Lightweight Tauri 2 desktop interface using the OS webview and plain HTML/CSS/JS.

---

## Repository Structure

```text
sentinel-av/
├── Cargo.toml                         # Virtual Cargo workspace (includes all crates + src-tauri)
├── .gitignore                         # Ignores /target, quarantine_vault/, *.pdb, .DS_Store
├── rules/
│   └── basic_threats.yar              # YARA signature rules loaded at scan time
├── crates/
│   ├── core-scanner/                  # File walker, 64 KB chunked SHA-256 hasher, YARA-X scanner
│   │   ├── Cargo.toml                 # Dependencies: sha2, walkdir, yara-x, serde
│   │   └── src/
│   │       ├── lib.rs                 # scan_directory_with_progress(), ScanResult, ScanReport
│   │       ├── hasher.rs              # sha256_file() streaming 64 KB chunks
│   │       └── matcher.rs             # load_rules() & scan_file_with_rules() via yara-x
│   ├── quarantine/                    # Safe file isolation & user-approved deletion
│   │   ├── Cargo.toml                 # Dependencies: serde, serde_json
│   │   └── src/lib.rs                 # quarantine_file(), list_quarantined(), restore_file(), delete_permanently()
│   ├── service-daemon/                # CLI / background daemon runner
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   └── kernel-sensor/                 # Placeholder for Windows Minifilter / Linux eBPF LSM
│       ├── Cargo.toml
│       └── src/lib.rs
└── apps/
    └── desktop-ui/
        ├── src/
        │   ├── index.html             # Single-file UI: Dark/Light mode, folder dropdown, live scan status, Quarantine Vault
        │   └── logo.png               # App icon source (used by `cargo tauri icon`)
        └── src-tauri/
            ├── Cargo.toml             # Dependencies: tauri, serde, serde_json, rfd, core-scanner, quarantine
            ├── tauri.conf.json        # Configured with `"withGlobalTauri": true` and `"frontendDist": "../src"`
            └── src/
                ├── main.rs            # Calls app_lib::run()
                └── lib.rs             # Tauri commands: get_common_folders, pick_custom_folder, scan_folder, get_quarantined, restore_item, delete_item
```

---

## Current Implementation Status

### Completed
- **Cargo Workspace & GitHub setup:** Root `Cargo.toml` and `.gitignore` configured.
- **`core-scanner`:**
  - Streams files in 64 KB chunks for SHA-256 (`sha2 = "0.10"`).
  - Compiles all `.yar` files from `rules/` using `yara-x = "1"` with `fast_scan(true)`.
  - Exposes `scan_directory_with_progress(root, rules_dir, on_file)` returning `ScanReport { files_scanned, duration_ms, findings }`.
- **`quarantine`:**
  - Streams flagged files into `quarantine_vault/<id>.quar` with a 64 KB XOR mask (`0xAA`) to neutralize executables, deletes the original, and writes `<id>.json` metadata (`QuarantineEntry`).
  - Supports `restore_file` (unmasks back to `original_path`) and `delete_permanently`.
- **`apps/desktop-ui` (Tauri 2):**
  - `get_common_folders` resolves OS-specific `Downloads`, `Desktop`, `Documents`, and `Full User Folder`.
  - `pick_custom_folder` opens the native OS folder picker via `rfd = "0.17"`.
  - `scan_folder` runs asynchronously via `tauri::async_runtime::spawn_blocking` and emits `"scan-progress"` events (`count`, `current_file`) to the frontend.
  - UI includes Dark/Light theme toggle (`localStorage`), button shadows, gradient hover effects, live scan progress pill, and Quarantine Vault action cards.

### Pending / Next Milestones
1. **Sync `service-daemon`:** Update `crates/service-daemon/src/main.rs` to call `core_scanner::scan_directory_with_progress` (since `scan_directory` was replaced).
2. **Clean-file hash cache:** Store `(path, modified_timestamp, sha256)` in a lightweight local cache (e.g., SQLite or compact binary map) so repeat scans skip unchanged clean files.
3. **Expanded YARA ruleset:** Add community YARA rules for trojans, spyware, and malware into `rules/` and support compiled rule caching (`Rules::serialize` / `deserialize`) for instant startup.
4. **Kernel-level monitoring (`crates/kernel-sensor`):** Implement a Windows File System Minifilter (e.g., via `windows-drivers-rs`) or Linux eBPF LSM hook inside a test VM, forwarding file open/execute events to `service-daemon` over IPC.

---

## Common Commands

```powershell
# Run the desktop app in development mode (from apps/desktop-ui)
cargo tauri dev

# Check all workspace crates compile (from sentinel-av root)
cargo check --workspace

# Regenerate app icons after replacing logo.png (from apps/desktop-ui)
cargo tauri icon src\logo.png

# Commit and push changes to GitHub (from sentinel-av root)
git add .
git commit -m "Describe changes"
git push
```
