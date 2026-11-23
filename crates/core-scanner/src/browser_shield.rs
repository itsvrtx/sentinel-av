use std::path::Path;

const SENSITIVE_PATTERNS: &[&str] = &[
    "login data",
    "web data",
    "cookies",
    "local state",
    "logins.json",
    "key4.db",
    "wallet.dat",
    "electrum",
    "exodus.wallet",
];

const AUTHORIZED_BROWSER_EXECUTABLES: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "brave.exe",
    "firefox.exe",
    "opera.exe",
    "vivaldi.exe",
];

/// Checks if a filesystem path targets sensitive browser credentials, cookies, or crypto wallets.
pub fn is_sensitive_credential_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    SENSITIVE_PATTERNS.iter().any(|&pattern| path_str.contains(pattern))
}

/// Checks if a requesting process is an authorized web browser.
pub fn is_authorized_browser_process(process_name: &str) -> bool {
    let name_lower = process_name.to_lowercase();
    AUTHORIZED_BROWSER_EXECUTABLES.iter().any(|&auth| name_lower == auth)
}

/// Evaluates if an access attempt to a browser credential vault should be blocked.
pub fn should_block_credential_access(process_name: &str, target_path: &Path) -> bool {
    if is_sensitive_credential_path(target_path) {
        !is_authorized_browser_process(process_name)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_shield() {
        let chrome_login_data = Path::new("C:/Users/User/AppData/Local/Google/Chrome/User Data/Default/Login Data");
        assert!(is_sensitive_credential_path(chrome_login_data));

        // Authorized browser is allowed
        assert!(!should_block_credential_access("chrome.exe", chrome_login_data));

        // Stealer / untrusted script / malware is blocked
        assert!(should_block_credential_access("python.exe", chrome_login_data));
        assert!(should_block_credential_access("powershell.exe", chrome_login_data));
        assert!(should_block_credential_access("stealer.exe", chrome_login_data));
    }
}
