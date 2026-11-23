# Pre-Release Task: Rule Bundling & Per-File AES-GCM Quarantine Encryption

## Objective
Prepare **Sentinel AV (v0.1.0)** for standalone `.exe` and Windows installer distribution so that:
1. The compiled `.exe` works from **any folder on any PC** without needing the source repository's `rules/` directory on disk.
2. Quarantined files in `crates/quarantine/src/lib.rs` are neutralized using **AES-256-GCM authenticated encryption with a unique per-file random key**, replacing the static `0xAA` XOR mask while keeping RAM usage flat via 64 KB chunked streaming.

---

## Task 1 — Bundle & Embed `rules/*.yar` for Standalone `.exe` Execution

### Problem
`apps/desktop-ui/src-tauri/src/lib.rs` currently looks for `rules/` or `../../rules` relative to the current working directory. When a user runs `sentinel-av.exe` from `Program Files`, `Downloads`, or `Desktop`, those relative paths will not exist.

### Implementation Steps
1. **Guarantee Embedded Fallback Rules in `crates/core-scanner/src/matcher.rs`:**
   - Ensure `core-scanner` embeds all built-in `.yar` files (`rules/basic_threats.yar`, `rules/eicar.yar`, `rules/malware_signatures.yar`) at compile time using `include_str!` (or compiled YARA-X ruleset bytes) so `core-scanner` **always** has a working ruleset even if no `rules/` folder exists on disk.
   - **False-Positive Precaution:** Avoid leaving raw EICAR test strings in plain text inside the compiled `.exe` if possible (e.g., construct or decode the EICAR rule string at runtime or use YARA-X's serialized compiled rules) so Windows Defender does not flag `sentinel-av.exe` itself.
2. **Bundle `rules/` via Tauri Resources (`apps/desktop-ui/src-tauri/tauri.conf.json`):**
   - Under `"bundle"`, add `"resources": ["../../rules/*.yar"]` so external/updatable `.yar` files are also packaged into the installer alongside the binary.
3. **Update Rule Path Resolution (`apps/desktop-ui/src-tauri/src/lib.rs`):**
   - In `scan_folder` (and any signature-listing command), resolve the rules directory in this order:
     1. Tauri's `app.path().resource_dir()` -> `rules/` (installed `.exe` / bundle path)
     2. Local dev paths (`rules/`, `../../rules/`)
     3. Embedded ruleset fallback in `core-scanner` (never fail a scan just because an external `rules/` folder is missing).
4. **Update `service-daemon` (`crates/service-daemon/src/main.rs`):**
   - Ensure `service-daemon` also falls back to the embedded ruleset when run outside the repo root.

---

## Task 2 — Replace Static `0xAA` XOR with Per-File Random Key AES-256-GCM

### Problem
`crates/quarantine/src/lib.rs` currently uses a hardcoded single-byte XOR mask (`const XOR_KEY: u8 = 0xAA`). Any script or malware can trivially reverse it, and there is no integrity check if a `.quar` file is modified.

### Implementation Steps
1. **Add Dependencies (`crates/quarantine/Cargo.toml`):**
   - Add [`aes-gcm`](https://crates.io/crates/aes-gcm) (`"0.10"`) and `hex = "0.4"` (using `aes_gcm::aead::{Aead, KeyInit, OsRng}` so no extra RNG crate version mismatch occurs).
2. **Streamed 64 KB Chunked AES-256-GCM Format (`crates/quarantine/src/lib.rs`):**
   - Do **not** read the entire file into a `Vec<u8>` (that would spike RAM on large files). Instead, encrypt/decrypt in **64 KB chunks** using a framed binary format:
     - Write a 4-byte magic header (e.g., `b"SQV1"`) so the format is identifiable.
     - For each 64 KB plaintext chunk:
       1. Generate a unique 12-byte nonce (`Aes256Gcm::generate_nonce(&mut OsRng)`).
       2. Encrypt the chunk with `cipher.encrypt(&nonce, &buffer[..n])`.
       3. Write `[u32 little-endian ciphertext length][12-byte nonce][ciphertext + 16-byte GCM tag]` to the `.quar` file.
   - **Per-File Random Key:**
     - Generate a fresh 256-bit key per quarantined file (`let key = Aes256Gcm::generate_key(&mut OsRng);`).
     - Store `key_hex: String` (or base64) in `QuarantineEntry` inside `<id>.json` (and zeroize/drop the key in memory after use).
     - Restrict permissions on the `quarantine_vault/` directory/files where supported, and never expose `key_hex` in UI responses if not needed (mark `#[serde(skip_serializing)]` or keep it strictly backend-side in the `.json` metadata struct).
   - **Decryption (`restore_file`):**
     - Verify the `b"SQV1"` header, read each `[len][nonce][ciphertext+tag]` frame, decrypt and authenticate with `cipher.decrypt(&nonce, payload)`, and write to the restored path.
     - If authentication fails (tampered `.quar` file), abort immediately, delete any partial restored file, and return an `io::ErrorKind::InvalidData` error.
3. **Add Automated Unit & Integration Tests (`crates/quarantine/src/lib.rs`):**
   - Add `#[cfg(test)] mod tests` using `std::env::temp_dir()`:
     - `test_quarantine_and_restore_roundtrip`: Create a test file, quarantine it, verify the original is gone and `.quar` differs from plaintext, restore it, and verify contents match byte-for-byte.
     - `test_tampered_quarantine_fails_auth`: Flip a byte in `.quar` and assert `restore_file` returns an error.
     - `test_delete_permanently`: Verify both `.quar` and `.json` are removed.

---

## Verification Checklist
1. Run `cargo test --workspace` from `sentinel-av/` — all unit and integration tests (including the new AES-GCM quarantine tests) must pass.
2. Build the release binary from `apps/desktop-ui/`:
   ```powershell
   cargo tauri build
   ```
3. **Standalone `.exe` Test (Outside Repo):**
   - Copy `target/release/app.exe` (or install via the generated NSIS `-setup.exe`) into an empty folder like `C:\Temp\sentinel_isolated\`.
   - Launch it and scan a test folder containing `SENTINEL-TEST-SIGNATURE`.
   - Confirm:
     - Rules load and detect the threat **without** a local `rules/` folder in `C:\Temp\sentinel_isolated\`.
     - The threat is isolated into `quarantine_vault\` using AES-256-GCM (`SQV1` header).
     - Clicking **Restore (Safe)** restores the exact original file, and clicking **Delete** permanently removes it.
