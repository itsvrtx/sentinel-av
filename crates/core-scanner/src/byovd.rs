use std::collections::HashSet;

/// Curated blocklist of known abused vulnerable driver (BYOVD / LOLDrivers) SHA-256 hashes.
const VULNERABLE_DRIVER_HASHES: &[&str] = &[
    // RTCore64.sys (Micro-Star International) - Arbitrary physical memory read/write
    "01a613623e32e821e1564f84693b4f62086c2e39ee4b5a0fb70bc1b9ec470a2c",
    // gdrv.sys (GIGABYTE) - Arbitrary memory read/write & MSR access
    "3f338d810842e47854cf0cc92e597bf682946c19f074d0a87611ab537446bc6e",
    // mhyprot2.sys (Genshin Anti-Cheat) - Kernel termination of security software
    "046e83da7a922379bb8cf1a21609121a978d3876ff7a2c6d7d4ecb99db6a72d7",
    // procexp.sys (Sysinternals Process Explorer vulnerable version)
    "9c7594fa7a030be9082eb00d876a38cf7896d8eb96b1b702ec8c991807d91e84",
    // Capcom.sys - Disables SMEP and executes arbitrary Ring-0 shellcode
    "4764b8d5a713b198850a04944439c2fffa488b09333331b26cc06bf8a6e9a657",
    // dbutil_2_3.sys (Dell BIOS utility) - Arbitrary physical memory R/W
    "06265988624e7561f5581f1e31d4d8efaa521d00d41e7cb76e0fbc4fb8f504ca",
    // asusio.sys (ASUSTeK Computer Inc)
    "a655291b9b188c03566144e019318b7631ce55a793c4e3e3b33de20579c8d197",
];

/// Checks whether a given driver file hash belongs to the known LOLDrivers vulnerable driver blocklist.
pub fn is_vulnerable_driver(sha256: &str) -> bool {
    let hash_lower = sha256.to_lowercase();
    VULNERABLE_DRIVER_HASHES.iter().any(|&v| hash_lower == v)
}

/// Returns the full list of embedded LOLDrivers hashes.
pub fn get_vulnerable_driver_hashes() -> HashSet<&'static str> {
    VULNERABLE_DRIVER_HASHES.iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byovd_blocklist() {
        assert!(is_vulnerable_driver("01a613623e32e821e1564f84693b4f62086c2e39ee4b5a0fb70bc1b9ec470a2c"));
        assert!(is_vulnerable_driver("4764B8D5A713B198850A04944439C2FFFA488B09333331B26CC06BF8A6E9A657"));
        assert!(!is_vulnerable_driver("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    }
}
