# Low-RAM Antivirus Blueprint & Master Specification

**Target Memory Footprint:** `< 30–50 MB` active background daemon RAM  
**Design Philosophy:** Event-driven kernel/OS hooks, memory-mapped static databases, zero background polling, trust-cached fast paths, and multi-layered behavioral + network defense against traditional malware, infostealers, rootkits, and modern staged backdoor attacks.

---

## 1. Core Detection & File Defense Engine

* **Real-Time On-Access File Scanner:**
  * Hooks directly into OS file system events (e.g., Windows Minifilter drivers or Linux `fanotify`) to inspect files *only* when created, modified, or executed—eliminating constant background disk polling.
* **Multi-Layered Static Analysis:**
  * **Cryptographic Hashing (`SHA-256`):** Instant zero-overhead blocking of known malicious binaries.
  * **Fuzzy Hashing (`SSDEEP`) & YARA Rules:** Detects mutated malware variants and targeted byte patterns without storing millions of redundant signatures.
  * **Executable Header & Entropy Inspection:** Inspects PE/ELF headers and calculates Shannon entropy to immediately flag packed, obfuscated, or malformed executables.
* **Dedicated Ransomware Shield & Micro-Rollback:**
  * Protects sensitive user directories (`Documents`, `Desktop`, `Pictures`, `Videos`) and terminates any untrusted process attempting rapid mass-file encryption or shadow-copy deletion (`vssadmin`, `wbadmin`).
  * **Copy-on-Write Micro-Rollback:** Maintains a capped `16 MB` copy-on-write backup ring buffer triggered only when an untrusted process opens a protected user file with `WRITE` access—allowing instant auto-restoration of any files touched before the threat is killed.
* **Cloud-Assisted Lookup & Offline Fallback:**
  * Offloads heavy reputation checks and unknown binary verdicts to a cloud API via asynchronous lightweight hash queries (strict `150 ms` timeout), gracefully falling back to local heuristics when offline.

---

## 2. Anti-Backdoor & Staged-Intrusion Defenses

Modern trojans rarely drop a single monolithic virus. Instead, they use tiny **loaders/droppers** or social-engineering lures (such as fake CAPTCHAs) to abuse built-in OS tools (**Living off the Land / LOLBins**), establish a **Command-and-Control (C2)** tunnel, and pull secondary payloads directly into memory.

### A. Process Lineage & LOLBin Correlation
* **Parent-Child Anomaly Detection:** Flags or blocks suspicious process trees—such as a browser, PDF reader, Office application, or script host spawning `cmd.exe`, `powershell.exe`, `mshta.exe`, or `wscript.exe`.
* **Real-Time Command-Line Inspection:** Hooks process creation events before execution completes to catch base64-encoded payloads (`-enc`), hidden window flags (`-w hidden`), and remote download commands (`Invoke-WebRequest`, `certutil -urlcache`, `curl`).

### B. Outbound Network & C2 Guardrails
* **Egress Lockdown on System Binaries:** Blocks or alerts when non-browser system utilities (`mshta.exe`, `certutil.exe`, `regsvr32.exe`, `rundll32.exe`) attempt outbound HTTP/HTTPS connections.
* **DNS Sinkholing & Reputation Filtering:** Intercepts DNS queries at the OS network layer to block newly registered domains (NRDs), abused dynamic DNS providers, and known C2 infrastructure.
* **Beaconing & Reverse-Shell Detection:** Flags untrusted processes holding persistent raw TCP sockets or emitting rhythmic, fixed-interval outbound heartbeats to external IPs.

### C. Anti-Persistence & Startup Lockdown
* **Persistence Surface Monitoring:** Watches high-abuse autostart locations (`HKCU\...\Run`, Scheduled Tasks, Windows Services, Startup folders, and WMI event subscriptions). Blocks unsigned binaries running from `AppData` or `Temp` from registering persistence.
* **AMSI (Antimalware Scan Interface) Integration:** Hooks into Windows AMSI so obfuscated PowerShell, VBScript, and JScript payloads are inspected *after* de-obfuscating themselves in memory, immediately prior to execution.

### D. Fileless & In-Memory Payload Traps
* **Cross-Process Injection Prevention:** Monitors suspicious cross-process API sequences (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) to stop loaders from hollowing legitimate system processes (`svchost.exe`, `explorer.exe`).
* **Targeted On-Demand Memory Sweeps:** Scans private memory pages *only* for processes that trigger a behavioral or network anomaly rather than sweeping all system RAM.

---

## 3. Advanced Attack Surface Shields

* **Credential & Infostealer Shield (Browser & LSASS Vault):**
  * Locks down sensitive browser profile files (`Login Data`, `Cookies`, `Local State`), crypto wallet directories, and `lsass.exe` memory handles inside the filesystem/object filter so only verified, signed parent binaries (e.g., `chrome.exe`, `msedge.exe`, `firefox.exe`) can read them.
* **Script, Archive & Mark-of-the-Web (MotW) Gatekeeping:**
  * Inspects `Zone.Identifier` alternate data streams on downloaded files and blocks script interpreters (`wscript.exe`, `cscript.exe`, `mshta.exe`) or weaponized `.lnk` shortcuts from executing payloads originating directly from `Downloads`, `Temp`, or mounted `.iso`/`.vhd` images.
* **BYOVD (Bring Your Own Vulnerable Driver) & Rootkit Defense:**
  * Hooks kernel driver load events (`NtLoadDriver`) and checks `.sys` hashes against an embedded blocklist of known vulnerable third-party drivers (`LOLDrivers`), preventing attackers from gaining Ring-0 access to blind the antivirus.
* **USB & Removable Media Quarantine:**
  * Automatically scans newly mounted USB volumes on arrival, blocks hidden-folder + `.lnk` autorun worm tricks, and monitors for abnormal, superhuman HID keystroke injection bursts (BadUSB / Rubber Ducky attacks).

---

## 4. Must-Have System, Performance & UX Features

* **Trust & Authenticode Signature Caching:**
  * Caches `(File Path + Mtime + Size + SHA-256)` of verified OS and trusted vendor binaries in an embedded key-value store so clean system files are never re-verified unless modified.
* **Encrypted Quarantine & One-Click Undo:**
  * Isolates detected threats by stripping execution permissions, renaming, and XOR/AES-encrypting the file. Never permanently deletes on first detection, allowing effortless one-click restoration and allowlisting for false positives.
* **Incremental Delta Definition Updates:**
  * Downloads tiny binary delta patches (a few kilobytes) and atomically swaps memory-mapped signature/Bloom filter files without restarting the background daemon.
* **Flexible Scanning Modes:**
  * **Quick Scan:** Targets high-risk zones (`AppData`, `Temp`, `System32`, startup entries, and active processes).
  * **Full System Scan:** Deep recursive traversal of all local drives.
  * **Custom / Context-Menu Scan:** Right-click scanning for individual files, folders, downloads, or USB drives.
* **Self-Defense Mechanism:**
  * Protects the antivirus background daemon, filter drivers, configuration files, and registry keys from termination (`taskkill`) or tampering by malware.
* **Exclusions & Allowlisting:**
  * Allows users to whitelist trusted developer folders, build directories, or specific binaries to eliminate false positives and preserve build speeds.
* **Silent / Game Mode & Adaptive Throttling:**
  * Automatically defers scheduled scans and suppresses pop-up alerts when fullscreen games, video calls, or high-CPU workloads are active.
* **Actionable Logs & Reporting:**
  * Clean, human-readable history of blocked threats, network blocks, scan durations, and quarantine actions.

---

## 5. Low-RAM Architecture & Engineering Rules

| Component / Layer | Engineering Strategy | Why It Saves RAM |
| :--- | :--- | :--- |
| **Core Daemon Language** | **Rust** or **C++** | Eliminates garbage collection spikes and heavy runtime VMs (`.NET`, JVM, Electron). |
| **Service / UI Separation** | Headless background service + on-demand GUI | Keeps the UI completely out of memory until the user explicitly opens the dashboard. |
| **Signature & Driver Storage** | Memory-mapped (`mmap`) files | Lets the OS kernel page signatures and vulnerable driver hashes in/out from disk automatically instead of allocating heap RAM. |
| **Fast-Negative Filtering** | In-memory **Bloom / Cuckoo Filters** (`~2–5 MB`) | Instantly clears 99% of clean files, safe domains, and non-blacklisted drivers without disk or network lookups. |
| **Infostealer File Vault** | Minifilter PID/Image path allowlist | Enforces browser credential protection inside the existing filesystem hook with zero extra RAM overhead. |
| **Micro-Rollback Buffer** | Capped `16 MB` Copy-on-Write ring buffer | Only triggers when a non-whitelisted process opens protected user files with `WRITE` access. |
| **Process & Network Hooks** | **ETW** (Process) + **WFP** `ALE_AUTH_CONNECT` (Network) | Event-driven streaming via tiny ring buffers; inspects connection handshakes without heavy deep-packet buffering. |
| **File Streaming & Threads** | Bounded worker pool + `64 KB` chunked reads | Scans multi-gigabyte archives/ISOs using fixed-size stack buffers instead of loading entire files into RAM. |
| **Behavioral Engine** | Compiled static finite-state decision trees | Runs directly as native machine code rather than embedding a heavy Python or Lua scripting VM. |
| **Trust Cache & Logs** | **SQLite** (WAL mode) or **redb / LMDB** (`2 MB` cache) | Keeps verified signature caches, scan logs, and quarantine metadata on disk rather than in heap memory. |

---

## 6. Phased Development Roadmap

* [ ] **Phase 1 (Core Daemon & Trust Cache):** Build native headless service in Rust/C++ with bounded thread pool, `SHA-256` + Bloom filter lookup, `redb`/SQLite trust cache, and encrypted quarantine vault.
* [ ] **Phase 2 (Real-Time File, Ransomware & Infostealer Shield):** Implement OS filesystem event hooks (`Minifilter` / `fanotify`), browser credential vault locks, and the `16 MB` copy-on-write ransomware rollback buffer.
* [ ] **Phase 3 (Anti-Backdoor, BYOVD & Network Guardrails):** Add ETW process/command-line monitoring, LOLBin/MotW script gatekeeping, AMSI script scanning, `NtLoadDriver` BYOVD blocking, and WFP outbound/DNS filtering.
* [ ] **Phase 4 (USB Shield, Usability & Self-Defense):** Add USB arrival/HID burst monitoring, daemon self-protection, delta updates, Game Mode throttling, and an on-demand lightweight UI.