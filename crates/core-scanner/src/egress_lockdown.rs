#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressBlockReason {
    RestrictedBinaryOutbound { binary: String, port: u16 },
}

const RESTRICTED_EGRESS_BINARIES: &[&str] = &[
    "mshta.exe",
    "certutil.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "bitsadmin.exe",
    "cscript.exe",
    "wscript.exe",
];

/// Checks if a system binary is prohibited from initiating outbound HTTP/HTTPS/TCP connections.
pub fn is_egress_restricted(binary: &str) -> bool {
    let lower = binary.to_lowercase();
    RESTRICTED_EGRESS_BINARIES.iter().any(|&b| lower == b || lower.ends_with(b))
}

/// Evaluates outbound connection policy for a binary targeting a destination port.
pub fn evaluate_egress_policy(binary: &str, dest_port: u16) -> Result<(), EgressBlockReason> {
    if is_egress_restricted(binary) {
        // Block all standard outbound internet traffic (80, 443, 8080, etc.)
        if dest_port == 80 || dest_port == 443 || dest_port == 8080 || dest_port == 8443 {
            return Err(EgressBlockReason::RestrictedBinaryOutbound {
                binary: binary.to_string(),
                port: dest_port,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_egress_lockdown() {
        assert!(evaluate_egress_policy("certutil.exe", 80).is_err());
        assert!(evaluate_egress_policy("mshta.exe", 443).is_err());
        assert!(evaluate_egress_policy("C:\\Windows\\System32\\regsvr32.exe", 8080).is_err());

        // Legitimate browser or dev tool allowed
        assert!(evaluate_egress_policy("chrome.exe", 443).is_ok());
        assert!(evaluate_egress_policy("cargo.exe", 443).is_ok());
    }
}
