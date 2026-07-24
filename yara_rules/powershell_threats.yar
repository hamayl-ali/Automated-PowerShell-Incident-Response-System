/*
  powershell_threats.yar
  ------------------------
  YARA rules for common malicious PowerShell indicators. Designed to scan
  both raw/decoded PowerShell command text and quarantined .ps1 files.
*/

rule Mimikatz_Keywords
{
    meta:
        description = "Detects Mimikatz-related keywords indicating credential dumping"
        severity = "critical"
        mitre = "T1003"
    strings:
        $a = "sekurlsa" nocase
        $b = "invoke-mimikatz" nocase
        $c = "logonpasswords" nocase
        $d = "lsadump" nocase
    condition:
        any of them
}

rule AMSI_Bypass_Reflection
{
    meta:
        description = "Detects AMSI bypass via .NET reflection against AmsiUtils"
        severity = "critical"
        mitre = "T1562.001"
    strings:
        $a = "amsiutils" nocase
        $b = "amsiinitfailed" nocase
        $c = "amsiscanbuffer" nocase
    condition:
        any of them
}

rule Base64_Encoded_PowerShell_Flag
{
    meta:
        description = "Detects the -enc / -encodedcommand PowerShell flag used to obfuscate payloads"
        severity = "high"
        mitre = "T1027"
    strings:
        $a = "-enc " nocase
        $b = "-encodedcommand" nocase
    condition:
        any of them
}

rule Remote_Download_Cradle
{
    meta:
        description = "Detects common PowerShell remote download cradle patterns"
        severity = "high"
        mitre = "T1105"
    strings:
        $a = "downloadstring" nocase
        $b = "net.webclient" nocase
        $c = "invoke-webrequest" nocase
        $d = "start-bitstransfer" nocase
    condition:
        any of them
}

rule Persistence_Registry_Run_Key
{
    meta:
        description = "Detects registry Run key persistence via PowerShell"
        severity = "high"
        mitre = "T1547.001"
    strings:
        $a = "currentversion\\run" nocase
        $b = "new-itemproperty" nocase
    condition:
        all of them
}

rule Defense_Evasion_Disable_Realtime_Monitoring
{
    meta:
        description = "Detects an attempt to disable Windows Defender real-time monitoring"
        severity = "medium"
        mitre = "T1562"
    strings:
        $a = "disablerealtimemonitoring" nocase
    condition:
        $a
}
