#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConnection {
    pub pid: u32,
    pub local_addr: String,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
}

const COMMON_REVERSE_SHELL_PORTS: &[u16] = &[4444, 1337, 8888, 9001, 6667, 7777];

const SYSTEM_SHELL_BINARIES: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "nc.exe",
    "ncat.exe",
    "netcat.exe",
    "bash.exe",
];

/// Evaluates network connection telemetry to detect reverse-shells and suspicious C2 beaconing.
pub fn evaluate_connection_risk(
    _pid: u32,
    process_name: &str,
    remote_port: u16,
) -> Option<String> {
    let lower = process_name.to_lowercase();
    let is_shell = SYSTEM_SHELL_BINARIES.iter().any(|&s| lower == s || lower.ends_with(s));

    if is_shell {
        return Some(format!(
            "Interactive system shell '{process_name}' has established an outbound socket on port {remote_port}"
        ));
    }

    if COMMON_REVERSE_SHELL_PORTS.contains(&remote_port) {
        return Some(format!(
            "Process '{process_name}' connected to high-risk reverse-shell port {remote_port}"
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_connection_risk_evaluation() {
        // Reverse shell via powershell or netcat
        let alert = evaluate_connection_risk(1234, "powershell.exe", 4444);
        assert!(alert.is_some());
        assert!(alert.unwrap().contains("Interactive system shell"));

        let alert2 = evaluate_connection_risk(5678, "malware.exe", 1337);
        assert!(alert2.is_some());
        assert!(alert2.unwrap().contains("high-risk reverse-shell port"));

        // Normal browser traffic
        assert_eq!(evaluate_connection_risk(9999, "chrome.exe", 443), None);
    }
}
