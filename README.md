# Sentinel AV

**A free, open-source, low-RAM antivirus built in Rust & Tauri 2 — engineered under human supervision to explore the depth of AI-assisted systems programming.**

[License: MIT](https://www.google.com/search?q=LICENSE)
[](https://www.rust-lang.org/)
[](https://v2.tauri.app/)

&lt;p align=&quot;center&quot;&gt;
  &lt;img src=&quot;screenshots/image.png&quot; alt=&quot;Sentinel AV Threat Scanner&quot; width=&quot;820&quot; /&gt;
  &lt;br /&gt;
  &lt;sub&gt;&lt;b&gt;Threat Scanner&lt;/b&gt; — Live YARA-X folder scanning with real-time file progress&lt;/sub&gt;
&lt;/p&gt;

---

## Why Rust + Tauri 2?

Traditional antivirus suites often bundle heavy runtimes, background updaters, or Chromium-based Electron shells that consume hundreds of megabytes of RAM before a scan even starts. **Sentinel AV** was built from the ground up with:

- **Rust (`core-scanner`, `quarantine`, `kernel-sensor`, `service-daemon`):** Zero garbage-collector pauses, predictable memory usage, and compile-time memory safety—essential for security software that parses untrusted binaries and executables.
- **Tauri 2 + Vanilla HTML/CSS/JS (`apps/desktop-ui`):** Uses the operating system's native webview (WebView2 on Windows) instead of shipping a second browser, keeping the UI binary small and RAM usage low.
- **YARA-X (`yara-x`):** VirusTotal's pure-Rust YARA engine for fast, memory-safe pattern matching against trojans, RATs, webshells, ransomware notes, and infostealers.

---

## Key Features

### Low-RAM Streaming Architecture
- **64 KB Chunked I/O:** File hashing (`sha2`) and quarantine encryption stream files in fixed 64 KB buffers so scanning multi-gigabyte files never spikes RAM.
- **Fast-Negative Bloom Filter & Trust Cache:** `bloom.rs` and `trust_cache.rs` (`path + mtime + size + sha256`) skip unchanged clean files on repeat scans.
- **Memory-Mapped Signatures (`mmap_store.rs`):** Loads signature databases without copying everything onto the heap.
- **Capped 16 MB CoW Micro-Rollback (`rollback.rs`):** Bounded ring buffer for ransomware file-write protection.
- **Game Mode (`game_mode.rs`):** Defers background scan work when active so gaming or heavy workloads stay smooth.

&lt;p align=&quot;center&quot;&gt;
  &lt;img src=&quot;screenshots/image-1.png&quot; alt=&quot;Sentinel AV Low RAM Usage&quot; width=&quot;720&quot; /&gt;
  &lt;br /&gt;
  &lt;sub&gt;&lt;b&gt;Low Memory Footprint&lt;/b&gt; — Minimal RAM consumption during operation&lt;/sub&gt;
&lt;/p&gt;

### Detection, Quarantine & Notifications
- **YARA-X Rule Engine (`rules/*.yar`):** Embedded and external `.yar` rules for trojans, droppers, RATs, webshells, PowerShell downloaders, ransomware notes, and reverse shells (with `std::hint::black_box` protection so embedded test signatures don't trigger false positives on the binary itself).
- **Per-File AES-256-GCM Quarantine Vault (`crates/quarantine`):** Neutralizes flagged files using 64 KB chunked AES-256-GCM authenticated encryption with a unique random key per file (`SQV1` format). **Nothing is ever deleted silently**—users can inspect the threat rule, original path, and SHA-256 hash, then choose **Restore (Safe)** or **Delete**.
- **Native Windows Toast Notifications:** Sends Windows notifications when a scan completes cleanly or when a threat is detected—urging immediate action and bringing Sentinel AV straight to the **Quarantine Vault** tab when clicked.

&lt;table&gt;
  &lt;tr&gt;
    &lt;td align=&quot;center&quot; width=&quot;50%&quot;&gt;
      &lt;img src=&quot;screenshots/image-2.png&quot; alt=&quot;Quarantine Vault&quot; width=&quot;100%&quot; /&gt;
      &lt;br /&gt;
      &lt;sub&gt;&lt;b&gt;Quarantine Vault&lt;/b&gt; — User-approved Restore &amp; Delete&lt;/sub&gt;
    &lt;/td&gt;
    &lt;td align=&quot;center&quot; width=&quot;50%&quot;&gt;
      &lt;img src=&quot;screenshots/Screenshot%20(1).png&quot; alt=&quot;Windows Toast Notification&quot; width=&quot;100%&quot; /&gt;
      &lt;br /&gt;
      &lt;sub&gt;&lt;b&gt;Windows Notification&lt;/b&gt; — Instant scan &amp; threat alerts&lt;/sub&gt;
    &lt;/td&gt;
  &lt;/tr&gt;
&lt;/table&gt;

### User-Friendly 5-Tab Desktop UI & System Tray
- **Threat Scanner:** Quick location shortcuts (Downloads, Desktop, Documents), native File Explorer folder picker (`rfd`), live file-by-file progress stream, and collapsible scanned-files history.
- **Quarantine Vault:** Searchable vault cards with threat descriptions, **Restore (Safe)**, **Restore All**, and **Delete**.
- **Process Monitor:** Live auto-refreshing task list with sortable **CPU %** and **Memory** columns, search filter, suspicious-process highlighting, and a **Task Inspector** (executable path, command-line args, **Open File Location**, **Scan File with Sentinel**, and **End Task**).
- **Signatures & Scan Logs:** View active YARA-X rules and persistent JSONL scan audit logs (`scan_log.rs`), plus **Dark/Light mode**, **Fullscreen (`F11`)**, and **System Tray** integration.

&lt;table&gt;
  &lt;tr&gt;
    &lt;td align=&quot;center&quot; width=&quot;50%&quot;&gt;
      &lt;img src=&quot;screenshots/image-4.png&quot; alt=&quot;Process Monitor &amp; Task Inspector&quot; width=&quot;100%&quot; /&gt;
      &lt;br /&gt;
      &lt;sub&gt;&lt;b&gt;Process Monitor&lt;/b&gt; — Sortable CPU/RAM &amp; Task Inspector&lt;/sub&gt;
    &lt;/td&gt;
    &lt;td align=&quot;center&quot; width=&quot;50%&quot;&gt;
      &lt;img src=&quot;screenshots/image-3.png&quot; alt=&quot;Sentinel AV Light Mode&quot; width=&quot;100%&quot; /&gt;
      &lt;br /&gt;
      &lt;sub&gt;&lt;b&gt;Light Mode&lt;/b&gt; — Clean, accessible theme toggle&lt;/sub&gt;
    &lt;/td&gt;
  &lt;/tr&gt;
&lt;/table&gt;

### Behavioral & Network Shields
- **Attack Surface Modules (`core-scanner` & `kernel-sensor`):** AMSI script buffer inspection (`amsi.rs`), Windows Mark-of-the-Web `:Zone.Identifier` checks (`motw.rs`), browser credential vault protection (`browser_shield.rs`), BYOVD vulnerable driver blocklist (`byovd.rs`), startup persistence checks (`persistence.rs`), process lineage analysis (`process_shield.rs`), DNS sinkholing (`dns_filter.rs`), egress lockdown (`egress_lockdown.rs`), network socket evaluation (`network_monitor.rs`), and USB autorun/LNK scanning (`usb.rs`).

> **Honest Scope Note (v0.1.0):** Sentinel AV currently operates as a **user-mode** scanner, quarantine vault, and behavioral/process monitor. True Windows kernel-mode drivers (File System Minifilter, WFP network callout, ETW kernel stream, and PPL self-defense) are planned as a future VM-tested phase, as distributing kernel drivers publicly on Windows requires an Extended Validation (EV) code-signing certificate.

---

## Why Shift to Sentinel AV?

1. **Free & Transparent:** No subscriptions, telemetry upsells, or bloated "PC optimizer" adware—every detection rule, scanned file path, and quarantine action is laid out clearly in front of you.
2. **Lightweight Footprint:** Built around streaming I/O, trust caching, and a native OS webview rather than heavy always-on background browsers.
3. **Inspectable & Auditable:** Modular Rust crates, human-readable YARA rules (`rules/*.yar`), and persistent JSONL scan logs (`scan_log.rs`).

---

## Repository Structure

```text
sentinel-av/
├── README.md
├── .gitignore
├── Cargo.toml                         # Workspace manifest
├── Cargo.lock
├── rules/                             # YARA-X signature rules (also embedded for standalone .exe)
│   ├── basic_threats.yar
│   ├── eicar.yar
│   └── malware_signatures.yar
├── crates/
│   ├── core-scanner/                  # YARA-X engine, chunked SHA-256, Bloom/trust cache, shields
│   ├── quarantine/                    # Per-file AES-256-GCM 64 KB chunked vault (restore/delete)
│   ├── kernel-sensor/                 # Directory watcher, USB & network monitor
│   └── service-daemon/                # Headless CLI / background scanner
└── apps/
    └── desktop-ui/                    # Tauri 2 desktop app (HTML/CSS/JS + Rust IPC commands)
```

---

## Getting Started

### Prerequisites
- [Rust](https://www.rust-lang.org/tools/install) (latest stable toolchain)
- Windows 10/11 (with WebView2 and Microsoft C++ Build Tools for Tauri)
- Tauri CLI v2:
  ```powershell
  cargo install tauri-cli --version "^2.0.0"
  ```

### Run in Development Mode
```powershell
git clone https://github.com/itsvrtx/sentinel-av.git
cd sentinel-av/apps/desktop-ui
cargo tauri dev
```

### Run Tests & Build Standalone `.exe` / Installer
```powershell
# Run workspace unit and integration tests (from repo root)
cargo test --workspace

# Build release binary and Windows installer (from apps/desktop-ui)
cargo tauri build
```

---

## AI-Assisted Engineering Disclosure

This entire project was built **under human supervision** to explore the depth and limits of modern AI-assisted software engineering—from zero prior systems/antivirus knowledge to a multi-crate Rust desktop application.

- **AI Models Used:** Claude, Gemini Hydrogen, DeepSeek v4.1, and Nemotron 3 Ultra
- **Workflow & Token Optimization:** Built using structured task specifications and **ponytail** skills to keep context focused and save tokens across iterations.
- **Human Role:** Architecture direction, UI/UX design decisions, manual testing, security review, and GitHub release management by [**itsvrtx**](https://github.com/itsvrtx).

---

## License

This project is licensed under the **MIT License** — free to use, modify, and distribute for everyone. See the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.