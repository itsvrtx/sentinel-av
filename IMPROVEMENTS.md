# Sentinel AV — Pre-Release Improvements & Hardening Plan

This checklist focuses on hardening existing features, fixing release blockers, and preparing **Sentinel AV** for standalone `.exe` and Windows installer distribution via [`cargo tauri build`](https://v2.tauri.app/distribute/windows-installer/).

---

## 1. Release Blockers (Must-Fix Before Distributing `.exe`) — [COMPLETED]

### Bundle YARA Rules Inside the Build — [DONE]
- **Status:** Bundled `../../../rules/*.yar` in `tauri.conf.json` resources and added dynamic bundle path resolution in `src-tauri/src/lib.rs` (`resolve_bundle_rules_dir`), with fallback to embedded signatures via `include_str!`.

### Rename the Output Binary — [DONE]
- **Status:** Renamed package to `sentinel-av`, binary to `sentinel-av`, and library to `sentinel_av_lib` in `apps/desktop-ui/src-tauri/Cargo.toml` and updated `src/main.rs`.

### Clean Up `service-daemon` Compilation — [DONE]
- **Status:** Aligned `service-daemon` with updated `scan_directory_with_progress` signature and verified clean workspace compilation.

---

## 2. Security & Reliability Hardening — [COMPLETED]

### Upgrade Quarantine Encryption — [DONE]
- **Status:** Replaced hardcoded static XOR byte mask with a per-file dynamic random key stored in `QuarantineEntry` with backward compatibility default (`0xAA`) while preserving 64 KB chunked streaming for flat RAM.

### Add End-to-End Integration Tests — [DONE]
- **Status:** Implemented end-to-end integration tests in `crates/quarantine` and `crates/core-scanner` covering scanning, detection, quarantine encryption verification, original file deletion, restore with SHA-256 validation, and permanent deletion of both `.quar` and `.json`.

### Harden Path & Permission Handling — [DONE]
- **Status:** Gracefully skipped OS-locked or permission-denied files in directory traversal, surfaced `files_skipped` in `ScanReport` and `ScanSummary`, and exposed it in desktop UI scan statistics.

---

## 3. Usability & Desktop Polish — [COMPLETED]

### System Tray & Background Mode — [DONE]
- **Status:** Implemented Tauri 2 system tray with "Open Dashboard", "Quick Scan", and "Quit" menu items; window close requested is intercepted to hide window instead of exiting.

### Quarantine Vault & Log UX — [DONE]
- **Status:**
  - Added "Restore All" in Vault and "Clear Clean Logs" in Scan Logs tab.
  - Added human-readable timestamps and one-line explanation of threat rules (`RULE_DESCRIPTIONS`) on each quarantined item.
  - Added dedicated "Scan Logs" navigation tab to inspect scan audit trail and clean entries.

---

## 4. Future Kernel-Level Milestone (VM Only)

- **Scope:** True kernel-mode hooks (Windows File System Minifilter, ETW real-time process stream, WFP `ALE_AUTH_CONNECT` network callout, and PPL self-defense).
- **Guideline:** Develop and test exclusively inside an isolated Virtual Machine. Public Windows distribution of kernel drivers requires an Extended Validation (EV) code-signing certificate and Microsoft attestation signing—keep the user-mode build as the primary free release until signing is ready.

---
