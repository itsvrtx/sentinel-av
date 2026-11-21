# Sentinel AV

A free, lightweight, open-source antivirus built in Rust.

## Project Structure
- `crates/core-scanner`: File walker, chunked SHA-256 hasher, and pattern matcher
- `crates/quarantine`: Safe file isolation & user-approved deletion
- `crates/service-daemon`: Low-RAM background scanning service
- `crates/kernel-sensor`: Kernel-level file/process monitor (Minifilter / eBPF)
- `apps/desktop-ui`: Tauri user interface
- `rules/`: YARA signature rules
