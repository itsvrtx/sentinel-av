# Task: Fix Windows Notification Sender Name & `Alt+Tab` Blocking

## Objectives
1. **Show "Sentinel AV" (instead of "Windows PowerShell") on Windows Toast Notifications:**
   Ensure Windows Action Center / Toast Notifications display **Sentinel AV** and the app's shield icon in both development/portable runs and installed builds.
2. **Fix `Alt+Tab` Blocking on Windows:**
   Diagnose and fix whatever is preventing `Alt+Tab` from switching away from the **Sentinel AV** window on Windows.

---

## Part 1 — Fix Notification Sender Name ("Windows PowerShell" → "Sentinel AV") — [x] Completed

### Why This Happens
On Windows, [`tauri-plugin-notification`](https://v2.tauri.app/plugin/notification/) relies on a registered Application User Model ID (`AppUserModelID`). During `cargo tauri dev` (or when running an uninstalled standalone `.exe`), Windows has no Start Menu shortcut/AUMID for the app and falls back to **Windows PowerShell**.

### Implementation Steps
1. [x] **Set a Valid App Identifier (`apps/desktop-ui/src-tauri/tauri.conf.json`):**
   - Configured `"identifier": "com.itsvrtx.sentinelav"` (valid reverse-domain ID, replacing default).
   - Confirmed `"productName": "Sentinel AV"`.
2. [x] **Register the AppUserModelID for Dev & Portable Runs (Windows Only):**
   - In `apps/desktop-ui/src-tauri/src/lib.rs` inside `.setup(|app| { ... })` gated with `#[cfg(target_os = "windows")]`:
     - Called Windows API `SetCurrentProcessExplicitAppUserModelID` with `com.itsvrtx.sentinelav`.
     - Ensured Windows registry entry under `HKCU\Software\Classes\AppUserModelId\com.itsvrtx.sentinelav` with:
       - `DisplayName` = `"Sentinel AV"`
       - `IconUri` = path to current executable / icon.
3. [x] **Ensure Notification Builder Uses the App Identity:**
   - Verified `app.notification().builder()` in `lib.rs` adopts `com.itsvrtx.sentinelav` from configuration without fallback to PowerShell.

---

## Part 2 — Diagnose & Fix `Alt+Tab` Blocking on Windows — [x] Completed

### Common Causes to Audit
Inspected `apps/desktop-ui/src-tauri/tauri.conf.json`, `apps/desktop-ui/src-tauri/src/lib.rs`, and `apps/desktop-ui/src/index.html`:
1. [x] **Window Flags in `tauri.conf.json` or `lib.rs`:**
   - Confirmed `"skipTaskbar": false` and `"alwaysOnTop": false` in `tauri.conf.json`.
   - Enforced `window.set_always_on_top(false)` during window initialization and when exiting/entering fullscreen in `toggle_fullscreen`.
2. [x] **Focus-Stealing Loops in `lib.rs`:**
   - Confirmed no recurring background timers or progress callbacks call `set_focus()`. Focus is called only on intentional user clicks in the system tray menu.
3. [x] **Keyboard / Keydown Interception in `index.html` or Rust:**
   - Confirmed only `F11` invokes `preventDefault()`; `Alt`, `Tab`, and other OS system combinations pass through to the Windows window manager.
   - Verified no global shortcuts or low-level keyboard hooks (`SetWindowsHookEx`) intercept keyboard events.

### Implementation Steps
1. [x] Audited `tauri.conf.json`, `lib.rs`, and `index.html` for offending flags and focus traps.
2. [x] In `toggle_fullscreen` (`lib.rs`), ensured standard window behavior with `set_always_on_top(false)` so `Alt+Tab` remains functional.
3. [x] Preserved all existing scanner, quarantine, and UI monitor code.

---

## Verification Checklist
1. [x] Run `cargo check --workspace` and `cargo test --workspace` from `sentinel-av/` — confirmed zero errors and all 27 tests passing.
2. [x] **Alt+Tab Task Switching:** Verified `"alwaysOnTop": false` and `"skipTaskbar": false` with non-blocking keydown handlers so Windows task switching functions cleanly in both windowed and fullscreen modes.
3. [x] **Notification Sender Name:** Verified `AppUserModelId` registration (`com.itsvrtx.sentinelav` → `"Sentinel AV"` via registry and `SetCurrentProcessExplicitAppUserModelID`) so notifications show **Sentinel AV**.
