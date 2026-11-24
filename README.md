# Sentinel AV

**A free, open-source, low-RAM antivirus desktop application built in Rust and Tauri 2.**

Sentinel AV is engineered for transparency, minimal memory overhead, and inspectable security. Developed with AI-assisted workflows under human supervision (**itsvrtx**) and licensed under the **MIT License**, it pairs a streaming Rust scanning and quarantine core with a lean native-webview desktop interface—without adware, subscriptions, or telemetry upsells.



## Why Rust + Tauri 2 + YARA-X

### Why Rust (`core-scanner`, `quarantine`, `kernel-sensor`, `service-daemon`)

* **Predictable memory behavior:** No garbage-collection pauses or runtime heap bloat during directory walks, hashing, or rule evaluation.

* **Compile-time memory safety:** Strong ownership and bounds guarantees when parsing untrusted files, binaries, and filesystem metadata.

### Why Tauri 2 + Vanilla HTML/CSS/JS (`apps/desktop-ui`)

* **Lean desktop footprint:** Instead of bundling a full Chromium runtime like Electron, Tauri 2 renders the interface using the operating system's native webview (**WebView2** on Windows).

* **Zero framework bloat:** The frontend lives in a single-file vanilla HTML/CSS/JS interface (`apps/desktop-ui/src/index.html`), keeping startup fast and memory usage minimal.

### Why YARA-X (`yara-x`)

* **Pure-Rust pattern matching:** Integrates `yara-x` directly in-process to compile and evaluate `.yar` rules for trojans, droppers, RATs, webshells, ransomware indicators, and infostealers without C FFI overhead.

### Why Choose Sentinel AV

* **Free and transparent:** Open-source codebase with no adware, paid tiers, or hidden telemetry upsells.

* **Low-memory streaming design:** Bounded chunked I/O and fast-skip caches prevent memory spikes on large files or repeated scans.

* **Fully auditable:** Every Rust crate, `.yar` signature file (`rules/*.yar`), and JSONL scan log can be inspected and verified directly.

## Applications, Tooling & AI Engineering Workflow

### Development & Runtime Stack

| Component | Role |
| :--- | :--- |
| **Rust Toolchain & Cargo** | Core workspace build, testing, and dependency management (`edition = "2024"`, `rust-version = "1.90"` in `src-tauri`) |
| **Tauri CLI v2** | Desktop bundling, IPC command bridge, system tray, and native notifications (`tauri = "2.12.7"`) |
| **WebView2** | Native Windows OS webview runtime powering the `apps/desktop-ui` interface |
| **VS Code** | Primary code editor and workspace environment |
| **Claude & Antigravity** | AI-assisted coding, architecture exploration, and task execution |

### AI Models & Human-Supervised Workflow

* **Models:** **Claude**, **Gemini Hydrogen**, **DeepSeek v4.1**, and **Nemotron 3 Ultra**

* **Workflow:** Structured task specifications paired with **ponytail** skills for context and token efficiency across multi-crate tasks.

* **Human Supervision (`itsvrtx`):** Architecture direction, UI/UX decisions, manual testing, security review, and release management.

## Architecture & Low-RAM Streaming Mechanics

Sentinel AV is designed to keep memory usage flat even when scanning large directory trees or multi-gigabyte files:

* **64 KB Chunked Streaming I/O (`hasher.rs`, `quarantine/src/lib.rs`):** Both SHA-256 hashing (`sha2`) and AES-256-GCM quarantine encryption/decryption stream files in fixed **64 KB** (`64 * 1024` bytes) chunks rather than loading entire files into RAM.

* **Bloom Filter (`bloom.rs`) & Trust Cache (`trust_cache.rs`):** Avoids re-scanning unchanged clean files by checking a fast-negative Bloom filter and a persistent trust cache keyed on file path, metadata (`mtime`, `size`), and SHA-256 hash (stored in `%LOCALAPPDATA%\SentinelAV\trust_cache.json` with a working-directory fallback).

* **Memory-Mapped Signatures (`mmap_store.rs`):** Supports memory-mapped signature storage so rule data does not need to be duplicated across heap allocations.

* **16 MB Bounded CoW Micro-Rollback (`rollback.rs`):** Provides a capped **16 MB** Copy-on-Write micro-rollback buffer for bounded recovery operations without unbounded memory growth.

* **Game Mode (`game_mode.rs`):** Detects active full-screen/gaming sessions and defers background scan work to avoid interrupting system performance.

## Detection, Quarantine Vault, Notifications & Shields

### YARA-X Rule Engine (`rules/*.yar`)

`crates/core-scanner/src/matcher.rs` compiles and runs `.yar` rules from `rules/` (resolved via `resolve_rules_dir`) alongside embedded fallback rules:

* `rules/basic_threats.yar` — General threat signatures including `Test_Suspicious_Pattern` and `Trojan_Generic_Dropper`.

* `rules/eicar.yar` — Standard `EICAR_Test_File` detection rule.

* `rules/malware_signatures.yar` — Behavioral and script indicators including `Suspicious_Webshell` (PHP webshell patterns) and `Suspicious_PowerShell_Downloader` (PowerShell download cradles, `certutil`, `bitsadmin`).

* **Self-False-Positive Prevention:** Embedded test patterns (such as `OBFUSCATED_EICAR` XOR-encoded with `0x5C`) are decoded using `std::hint::black_box` so the compiled binary does not trigger false positives on itself.

### Quarantine Vault (`crates/quarantine`)

* **Encrypted Storage (`SQV1` Format):** Flagged files are encrypted per-file using **AES-256-GCM** (`aes-gcm`) with `OsRng`-generated keys in **64 KB** chunks (`MAGIC_HEADER = b"SQV1"`), while retaining backwards-compatible XOR fallback support (`0xAA`).

* **Non-Destructive Workflows:** Users can inspect quarantined metadata (`id`, `original_path`, `sha256`, `rule`, `file_size`, `timestamp`) and choose **Restore (Safe)**, **Restore All**, or permanent **Delete**.



### Desktop UI & Native Notifications (`apps/desktop-ui`)

The Tauri 2 desktop application (`1140×780`, `com.itsvrtx.sentinelav`) includes:

* **Native Windows Toast Notifications:** Powered by `tauri-plugin-notification` for scan completion summaries and threat alerts that jump straight to the Quarantine Vault (`focus_and_open_vault`).

* **Threat Scanner Tab:** Quick folder shortcuts (`get_common_folders`), native OS folder picker via `rfd` (`pick_custom_folder`), live scan progress, and scan history.

* **Quarantine Vault Tab:** View quarantined threats, inspect hashes and matched rules, and restore or delete items.

* **Process Monitor Tab:** Live system process list (`sysinfo`) with sortable CPU and memory columns, search filtering, suspicious process highlighting, and a **Task Inspector** supporting **Open Location**, **Scan**, and **End Task**.

* **Signatures & Scan Logs Tab:** Inspect active YARA-X signatures (`get_active_signatures`) and persistent JSONL scan logs (`scan_log.rs`, with `clear_clean_logs`).

* **Shell Controls:** Dark/light theme toggle, Fullscreen (`F11`), and System Tray integration (`TrayIconBuilder` with close-to-tray interception).

| Process Monitor | Signatures & Scan Logs | Light / Additional View |
| :---: | :---: | :---: |
|  |  |  |



### Behavioral & Network Shields (`core-scanner` & `kernel-sensor`)

The workspace includes modular user-mode shield implementations across `crates/core-scanner/src/` and `crates/kernel-sensor/src/`:

* **Execution & Script Inspection:** `amsi.rs`, `motw.rs` (Mark-of-the-Web checks), `browser_shield.rs`, `process_shield.rs`, `memory_scanner.rs`, `entropy.rs`

* **Persistence & Driver Checks:** `persistence.rs`, `byovd.rs` (Bring Your Own Vulnerable Driver indicators)

* **Network & Peripheral Monitoring:** `dns_filter.rs`, `egress_lockdown.rs` (targets Living-off-the-Land binaries such as `mshta.exe`, `certutil.exe`, `regsvr32.exe`, `rundll32.exe`, `bitsadmin.exe`, `cscript.exe`, and `wscript.exe` on outbound ports `80`, `443`, `8080`, `8443`), `network_monitor.rs`, and `usb.rs`

## Honest Scope & Roadmap Note (`v0.1.0`)

Sentinel AV **v0.1.0** operates strictly in **user mode** (on-demand and watch-mode directory scanning, AES-256-GCM quarantine vault, process monitoring, and user-mode behavioral/network checks).

True Windows **kernel-mode** components—such as a filesystem minifilter driver, Windows Filtering Platform (WFP) callouts, kernel ETW streams, and Protected Process Light (PPL) enforcement—are **not** included in `v0.1.0`. They are planned for a future VM-tested phase due to Windows driver signing and EV code-signing certificate requirements.

## Repository Structure

```text
sentinel-av/
├── .cargo/                     # Cargo workspace configuration
├── Cargo.toml                  # Workspace manifest (5 member crates)
├── Cargo.lock                  # Locked dependency graph
├── rules/                      # YARA-X signature files
│   ├── basic_threats.yar
│   ├── eicar.yar
│   └── malware_signatures.yar
├── crates/
│   ├── core-scanner/           # YARA-X engine, streaming SHA-256, Bloom/trust cache, shields
│   ├── quarantine/             # AES-256-GCM (SQV1) 64 KB chunked quarantine vault
│   ├── kernel-sensor/          # User-mode DirectorySensor, network_monitor, usb
│   └── service-daemon/         # Headless CLI & --watch (-w) real-time folder scanner
├── apps/
│   └── desktop-ui/             # Tauri 2 app + Vanilla HTML/CSS/JS frontend (src/index.html)
└── screenshots/                # UI and system tray screenshots
```

## Prerequisites, Build & Test Commands

### Prerequisites (Windows)

* **Windows 10 / 11** with **Microsoft Edge WebView2** runtime

* **Microsoft C++ Build Tools** (Desktop development with C++)

* **Rust toolchain** (`rustup` / `cargo`, Rust **1.90+** required by `apps/desktop-ui/src-tauri`)

* **Tauri CLI v2:**

  ```powershell
  cargo install tauri-cli --version "^2.0.0"
  ```

### Clone, Run, Test & Build

```powershell
# 1. Clone the repository
git clone https://github.com/itsvrtx/sentinel-av.git
cd sentinel-av

# 2. Run the desktop app in development mode
cargo tauri dev

# 3. Run all workspace unit and integration tests
cargo test --workspace

# 4. Build release binaries and installer artifacts
cargo tauri build
```

## License

Sentinel AV is released under the **[MIT License](https://github.com/itsvrtx/sentinel-av/blob/main/LICENSE.md)**.
