// Sentinel AV - Basic Threat Signatures & Trojan Detection Rules

rule Test_Suspicious_Pattern {
    meta:
        description = "Internal test signature for verification"
        threat_level = "Low"
    strings:
        $test_sig = "SENTINEL-TEST-SIGNATURE" ascii wide
    condition:
        $test_sig
}

rule Trojan_Generic_Dropper {
    meta:
        description = "Detects generic Trojan droppers and memory-injection downloaders"
        threat_level = "Critical"
        category = "Trojan"
    strings:
        $inj1 = "VirtualAllocEx" ascii wide nocase
        $inj2 = "WriteProcessMemory" ascii wide nocase
        $inj3 = "CreateRemoteThread" ascii wide nocase
        $inj4 = "NtUnmapViewOfSection" ascii wide nocase
        $inj5 = "QueueUserAPC" ascii wide nocase

        $dl1 = "URLDownloadToFileA" ascii wide nocase
        $dl2 = "URLDownloadToFileW" ascii wide nocase
        $dl3 = "InternetReadFile" ascii wide nocase

        $drop1 = "cmd.exe /c start /b" ascii wide nocase
        $drop2 = "powershell -windowstyle hidden -enc" ascii wide nocase
        $drop3 = "wscript.shell.run" ascii wide nocase
    condition:
        (any of ($dl*) and any of ($inj*)) or
        (2 of ($inj*) and any of ($drop*))
}

rule Trojan_RAT_Indicator {
    meta:
        description = "Detects Remote Access Trojans (RATs) including AsyncRAT, NjRAT, Remcos, and Quasar"
        threat_level = "Critical"
        category = "Trojan"
    strings:
        $async1 = "AsyncClient" ascii wide nocase
        $async2 = "Pastebin" ascii wide nocase
        $async3 = "SslClient" ascii wide nocase

        $njrat1 = "netsh firewall add allowedprogram" ascii wide nocase
        $njrat2 = "cmd.exe /k ping 0.0.0.0 & del" ascii wide nocase
        $njrat3 = "[kl]" ascii wide nocase

        $remcos1 = "Remcos" ascii wide
        $remcos2 = "Breaking-Security" ascii wide
        $remcos3 = "Remcos Restarted" ascii wide

        $quasar1 = "Quasar.Common" ascii wide nocase
        $quasar2 = "QuasarClient" ascii wide nocase
    condition:
        (all of ($async*)) or
        (2 of ($njrat*)) or
        (any of ($remcos*)) or
        (any of ($quasar*))
}

rule Trojan_InfoStealer_Vault {
    meta:
        description = "Detects Trojan info-stealers harvesting browser credentials and tokens"
        threat_level = "High"
        category = "Trojan"
    strings:
        $sqlite1 = "SELECT * FROM logins" ascii wide nocase
        $sqlite2 = "SELECT encrypted_value FROM cookies" ascii wide nocase
        $sqlite3 = "SELECT host_key, name, value, path FROM cookies" ascii wide nocase
        $sqlite4 = "SELECT * FROM moz_logins" ascii wide nocase

        $target1 = "\\AppData\\Local\\Google\\Chrome\\User Data" ascii wide nocase
        $target2 = "\\Discord\\Local Storage\\leveldb" ascii wide nocase
        $target3 = "\\Telegram Desktop\\tdata" ascii wide nocase
        $target4 = "wallet.dat" ascii wide nocase

        $hook1 = "SetWindowsHookEx" ascii wide nocase
        $hook2 = "GetAsyncKeyState" ascii wide nocase
        $hook3 = "GetKeyboardState" ascii wide nocase
    condition:
        (any of ($sqlite*) and any of ($target*)) or
        (any of ($sqlite*) and any of ($hook*))
}
