# Sentinel AV — AIM.md Implementation Status Report

**Generated:** 2026-11-23  
**Target:** `< 30–50 MB` active background daemon RAM  
**Design Philosophy:** Event-driven kernel/OS hooks, memory-mapped static databases, zero background polling, trust-cached fast paths, multi-layered behavioral + network defense.

---

## Executive Summary

| Metric | Value |
|--------|-------|
| **Overall Implementation** | ~25% |
| **Phase 1 (Core Daemon & Trust Cache)** | ~50% |
| **Phase 2 (Real-Time File, Ransomware & Infostealer)** | ~5% |
| **Phase 3 (Anti-Backdoor, BYOVD & Network)** | ~5% |
| **Phase 4 (USB, Self-Defense, Usability)** | ~10% |

**Verdict:** Solid on-demand scanner + UI foundation. **Zero kernel/real-time components.** Not yet an antivirus with real-time protection.

---

## Section-by-Section Status

### 1. Core Detection & File Defense Engine (~60%)

| Feature | Status | Notes |
|---------|--------|-------|
| Real-Time On-Access File Scanner (Minifilter/fanotify) | ❌ **Missing** | `kernel-sensor` crate is a placeholder (`sensor_placeholder()`) |
| Cryptographic Hashing (SHA-256) | ✅ **Complete** | `crates/core-scanner/src/hasher.rs` |
| Fuzzy Hashing (SSDEEP) & YARA Rules | ✅ **YARA only** | YARA-X via `yara-x` crate; SSDEEP not implemented |
| Executable Header & Entropy Inspection | ❌ **Missing** | No PE/ELF parsing, no Shannon entropy calculation |
| Ransomware Shield & 16 MB CoW Micro-Rollback | ❌ **Missing** | No filesystem event hooks, no rollback buffer |
| Cloud-Assisted Lookup + Offline Fallback | ❌ **Missing** | No cloud API, no reputation checks |

---

### 2. Anti-Backdoor & Staged-Intrusion Defenses (~10%)

| Feature | Status | Notes |
|---------|--------|-------|
| **A. Process Lineage & LOLBin Correlation** | | |
| Parent-Child Anomaly Detection (ETW) | ❌ **Missing** | UI uses `sysinfo` polling, not ETW |
| Real-Time Command-Line Inspection | ❌ **Missing** | No process creation hooks |
| **B. Outbound Network & C2 Guardrails** | | |
| Egress Lockdown on System Binaries (WFP) | ❌ **Missing** | No Windows Filtering Platform integration |
| DNS Sinkholing & Reputation Filtering | ❌ **Missing** | No DNS interception |
| Beaconing & Reverse-Shell Detection | ❌ **Missing** | No network flow analysis |
| **C. Anti-Persistence & Startup Lockdown** | | |
| Persistence Surface Monitoring | ❌ **Missing** | No autostart/registry/service/WMI watching |
| AMSI Integration | ❌ **Missing** | No `amsi.dll` hooking |
| **D. Fileless & In-Memory Payload Traps** | | |
| Cross-Process Injection Prevention | ❌ **Missing** | No `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` monitoring |
| Targeted On-Demand Memory Sweeps | ❌ **Missing** | No memory scanning capability |

---

### 3. Advanced Attack Surface Shields (~5%)

| Feature | Status | Notes |
|---------|--------|-------|
| Credential & Infostealer Shield (Browser, LSASS) | ❌ **Missing** | No minifilter PID/image allowlist |
| Script, Archive & Mark-of-the-Web Gatekeeping | ❌ **Missing** | No `Zone.Identifier` ADS inspection |
| BYOVD & Rootkit Defense (`NtLoadDriver`) | ❌ **Missing** | No driver load monitoring, no LOLDrivers blocklist |
| USB & Removable Media Quarantine | ❌ **Missing** | No USB arrival/HID burst monitoring |

---

### 4. Must-Have System, Performance & UX Features (~50%)

| Feature | Status | Notes |
|---------|--------|-------|
| Trust & Authenticode Signature Caching | ❌ **Missing** | Rules recompiled every scan; no `(path+mtime+size+sha256)` cache |
| Encrypted Quarantine & One-Click Undo | ✅ **Complete** | XOR masking + JSON metadata; restore/delete works |
| Incremental Delta Definition Updates | ❌ **Missing** | No delta patches, no atomic mmap swap |
| Flexible Scanning Modes | ✅ **Complete** | Quick (UI shortcuts), Full (recursive), Custom (folder picker) |
| Self-Defense Mechanism | ❌ **Missing** | No daemon/driver/config protection |
| Exclusions & Allowlisting | ❌ **Missing** | No whitelist support |
| Silent / Game Mode & Adaptive Throttling | ❌ **Missing** | No fullscreen/game detection |
| Actionable Logs & Reporting | ⚠️ **Minimal** | Only in-app toast notifications; no persistent log file |

---

### 5. Low-RAM Architecture & Engineering Rules (~30%)

| Component / Layer | Strategy | Status | Notes |
|-------------------|----------|--------|-------|
| Core Daemon Language | Rust | ✅ **Complete** | All crates in Rust |
| Service / UI Separation | Headless + on-demand GUI | ✅ **Complete** | Tauri 2 + `service-daemon` binary |
| Signature & Driver Storage | Memory-mapped (`mmap`) files | ❌ **Missing** | YARA rules loaded into heap via `yara-x` |
| Fast-Negative Filtering | Bloom / Cuckoo Filters (~2–5 MB) | ❌ **Missing** | No probabilistic filter; scans every file |
| Infostealer File Vault | Minifilter PID/Image allowlist | ❌ **Missing** | No filesystem filter driver |
| Micro-Rollback Buffer | Capped 16 MB CoW ring buffer | ❌ **Missing** | Not implemented |
| Process & Network Hooks | ETW + WFP `ALE_AUTH_CONNECT` | ❌ **Missing** | Using `sysinfo` polling (high overhead) |
| File Streaming & Threads | Bounded pool + 64 KB chunks | ⚠️ **Partial** | 64 KB XOR streaming in quarantine only |
| Behavioral Engine | Compiled static decision trees | ❌ **Missing** | No behavioral engine; only YARA matching |
| Trust Cache & Logs | SQLite/redb/LMDB (2 MB cache) | ❌ **Missing** | No embedded DB; quarantine uses flat JSON files |

---

### 6. Phased Development Roadmap

| Phase | Target | Progress | Key Missing |
|-------|--------|----------|-------------|
| **Phase 1** | Core Daemon & Trust Cache | ~50% | Trust cache (redb/SQLite), Bloom filters, mmap signatures, delta updates |
| **Phase 2** | Real-Time File, Ransomware & Infostealer | ~5% | Minifilter/fanotify, CoW rollback, browser vault lock |
| **Phase 3** | Anti-Backdoor, BYOVD & Network | ~5% | ETW, WFP, AMSI, `NtLoadDriver`, DNS sinkholing |
| **Phase 4** | USB, Self-Defense, Usability | ~10% | USB/HID monitoring, daemon self-protection, Game Mode |

---

## What's Actually Working (✅)

- **YARA-X scanning** with 3 embedded rule files (`basic_threats.yar`, `eicar.yar`, `malware_signatures.yar`)
- **SHA-256 hashing** for quarantined files (`crates/core-scanner/src/hasher.rs`)
- **Encrypted quarantine vault** (XOR byte masking + JSON metadata) — `crates/quarantine/src/lib.rs`
- **Tauri 2 desktop UI** with 4 tabs: Scanner, Vault, Process Monitor, Signatures — `apps/desktop-ui/src/index.html`
- **On-demand folder scanning** with live progress events — `scan_directory_with_progress()`
- **Process listing** via `sysinfo` (polling-based, not event-driven)
- **Dark/light theme**, toast notifications, responsive layout
- **Service-daemon CLI** for manual scan + quarantine workflow

---

## Critical Gaps (Must Fix for MVP)

| Priority | Gap | Effort | Files to Create/Modify |
|----------|-----|--------|------------------------|
| **P0** | Real-time filesystem monitor (Minifilter on Windows) | High | New `kernel-sensor` implementation; `crates/kernel-sensor/src/lib.rs` |
| **P0** | Trust cache (redb/SQLite) for verified binaries | Medium | New crate or extend `core-scanner`; persistent `(path+mtime+size+sha256)` store |
| **P0** | Bloom/Cuckoo filter for fast-negative path | Medium | New crate `fast-filter`; integrate in `scan_directory_with_progress` |
| **P1** | Ransomware 16 MB CoW rollback buffer | High | Minifilter callback on `WRITE` to protected dirs; ring buffer in shared memory |
| **P1** | ETW process/command-line monitoring | High | New crate `etw-monitor`; parse `ProcessStart`/`CommandLine` events |
| **P1** | WFP outbound connection filtering | High | Kernel-mode WFP callout driver (`ALE_AUTH_CONNECT` layer) |
| **P2** | AMSI integration for script deobfuscation | Medium | `amsi.dll` hooking; scan `IAntimalware::Scan` content |
| **P2** | BYOVD blocklist (`NtLoadDriver` + LOLDrivers) | Medium | Driver load callback; embedded vulnerable driver hash list |
| **P2** | DNS sinkholing / beaconing detection | Medium | WFP `ALE_RESOURCE_ASSIGNMENT` for DNS; timing analysis |
| **P3** | USB arrival + HID burst monitoring | Medium | `WM_DEVICECHANGE` + raw input monitoring |
| **P3** | Daemon self-defense (anti-tamper) | Medium | Protected process light (PPL) or minifilter protect own files |
| **P3** | Incremental delta updates | Low | Binary diff patching; atomic mmap swap on reload |

---

## Codebase Structure

```
sentinel-av/
├── AIM.md                          # Master specification (this doc's source)
├── AIM_STATUS.md                   # This status report
├── apps/
│   └── desktop-ui/                 # Tauri 2 desktop app
│       ├── src/index.html          # Complete UI (4 tabs, theme, toasts)
│       └── src-tauri/src/lib.rs    # Tauri commands: scan, vault, processes
├── crates/
│   ├── core-scanner/               # YARA-X + SHA-256 scanning
│   │   ├── src/lib.rs              # scan_directory_with_progress()
│   │   ├── src/matcher.rs          # YARA rule loading (disk + embedded)
│   │   └── src/hasher.rs           # SHA-256 streaming
│   ├── quarantine/                 # XOR-encrypted vault
│   │   └── src/lib.rs              # quarantine/restore/delete + JSON meta
│   ├── service-daemon/             # CLI binary for manual ops
│   │   └── src/main.rs             # scan_folder + interactive quarantine
│   └── kernel-sensor/              # PLACEHOLDER ONLY
│       └── src/lib.rs              # sensor_placeholder() stub
├── rules/
│   ├── basic_threats.yar           # Test pattern, Trojan droppers, RATs, stealers
│   ├── eicar.yar                   # EICAR test file
│   └── malware_signatures.yar      # Webshells, PS downloaders, ransomware notes, reverse shells
└── test_lab/                       # Demo files for UI testing
```

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| **No real-time protection** — malware executes before scan | Critical | High | Implement Minifilter/ETW immediately (Phase 2) |
| **High RAM under load** — no Bloom filter, no mmap | High | Medium | Add fast-negative filter + mmap signatures |
| **No persistence** — quarantine/logs lost on reinstall | Medium | Low | Add redb/SQLite for trust cache + logs |
| **No self-defense** — malware can kill daemon | High | High | Implement PPL / minifilter self-protection |
| **Single-threaded scan** — no bounded worker pool | Medium | Medium | Add `rayon` thread pool with chunked streaming |

---

## Recommended Next Steps (Priority Order)

1. **Replace `kernel-sensor` placeholder** with Windows Minifilter driver (or `fanotify` on Linux) for on-access scanning
2. **Add `redb` trust cache** keyed by `(path, mtime, size, sha256)` — skip re-hashing clean files
3. **Add Bloom filter** (~3 MB) for YARA rule fast-negative — clear 99% of files before YARA scan
4. **Implement 16 MB CoW rollback** in minifilter on `WRITE` to protected user directories
5. **ETW process monitor** for parent-child anomaly + command-line inspection (LOLBins)
6. **WFP callout driver** for egress lockdown on system binaries + DNS interception
7. **AMSI hook** for PowerShell/VBScript/JScript deobfuscated content scanning
8. **Daemon self-protection** via PPL or minifilter protect-own-files

---

## Lean Findings (Code That Should Not Exist)

| Finding | Location | Action |
|---------|----------|--------|
| `kernel-sensor` crate is dead code | `crates/kernel-sensor/src/lib.rs` | Delete or implement fully |
| `sysinfo` polling in UI process tab | `apps/desktop-ui/src-tauri/src/lib.rs:122-130` | Replace with ETW event stream |
| Embedded YARA rules duplicated in `matcher.rs` | `crates/core-scanner/src/matcher.rs:5-7` | Remove if disk rules always present |
| XOR key hardcoded (`0xAA`) | `crates/quarantine/src/lib.rs:7` | Make configurable; consider AES-GCM |
| No integration tests for full scan→quarantine→restore | Missing | Add `#[test]` in `core-scanner` + `quarantine` |

---

*Generated by code review against AIM.md specification. Run `cargo test --workspace` to verify current test coverage.*