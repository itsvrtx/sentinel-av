rule Test_Suspicious_Pattern {
    meta:
        description = "Harmless test rule to verify scanner detection"
    strings:
        $test_sig = "SENTINEL-TEST-SIGNATURE"
    condition:
        $test_sig
}
