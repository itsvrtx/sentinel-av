rule EICAR_Test_File {
    meta:
        description = "Standard EICAR Antivirus Test File"
        threat_level = "Test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii wide
    condition:
        $eicar
}
