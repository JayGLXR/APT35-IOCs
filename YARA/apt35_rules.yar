/*
    APT35 (Charming Kitten) YARA Rules
    
    Detection rules for APT35 malware and tools
    Author: Calvexa Group, LLC
    Date: October 2025
*/

rule APT35_PowerShell_Backdoor {
    meta:
        description = "Detects APT35 PowerShell backdoor patterns"
        author = "Calvexa Group"
        date = "2025-10-01"
        threat_actor = "APT35"
        
    strings:
        $s1 = "IEX (New-Object Net.WebClient).DownloadString" ascii wide
        $s2 = "Start-Process powershell" ascii wide
        $s3 = "-enc" ascii wide
        $s4 = "-WindowStyle Hidden" ascii wide
        
    condition:
        3 of them
}

rule APT35_Web_Shell {
    meta:
        description = "Detects APT35 web shell patterns"
        author = "Calvexa Group"
        date = "2025-10-01"
        threat_actor = "APT35"
        
    strings:
        $php1 = "<?php @eval($_POST[" ascii
        $php2 = "system($_REQUEST[" ascii
        $asp1 = "<%eval request(" ascii
        $generic1 = "shell_exec" ascii
        $generic2 = "passthru" ascii
        
    condition:
        any of them
}

rule APT35_Credential_Harvester {
    meta:
        description = "Detects APT35 credential harvesting tools"
        author = "Calvexa Group"
        date = "2025-10-01"
        threat_actor = "APT35"
        
    strings:
        $s1 = "successful login" ascii wide
        $s2 = "session_list" ascii wide
        $s3 = "google_account" ascii wide
        $s4 = "Client Time Zone" ascii wide
        
    condition:
        3 of them
}

rule APT35_ProxyShell_Exploitation {
    meta:
        description = "Detects ProxyShell exploitation artifacts"
        author = "Calvexa Group"
        date = "2025-10-01"
        threat_actor = "APT35"
        CVE = "CVE-2021-34473, CVE-2021-34523, CVE-2021-31207"
        
    strings:
        $path1 = "/autodiscover/autodiscover.json" ascii wide
        $path2 = "/mapi/nspi" ascii wide
        $path3 = "/EWS/Exchange.asmx" ascii wide
        $header = "X-Rps-CAT" ascii wide
        
    condition:
        2 of them
}
