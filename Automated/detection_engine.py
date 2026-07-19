"""
detection_engine.py
--------------------
Analyzes PowerShell Script Block Logging events (Event ID 4104 style JSON)
and Process Creation events (Event ID 4688 style JSON) for suspicious
activity. Each rule is mapped to a MITRE ATT&CK technique.

Pure Python 3 stdlib. No external dependencies.
"""

import re
import base64
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Detection rules
# Each rule: (name, mitre_technique, mitre_tactic, severity, matcher_function)
# severity: "low" | "medium" | "high" | "critical"
# ---------------------------------------------------------------------------

def _has_encoded_command(cmdline: str) -> bool:
    return bool(re.search(r"-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", cmdline, re.I))


def _has_download_cradle(cmdline: str) -> bool:
    patterns = [
        r"(new-object\s+net\.webclient)",
        r"(invoke-webrequest|iwr)\s",
        r"(invoke-expression|iex)\s*\(",
        r"downloadstring\s*\(",
        r"start-bitstransfer",
    ]
    return any(re.search(p, cmdline, re.I) for p in patterns)


def _has_obfuscation(cmdline: str) -> bool:
    # Heavy backtick / char-concat / format-operator obfuscation
    backticks = cmdline.count("`")
    concat_ops = len(re.findall(r"'\s*\+\s*'", cmdline))
    format_op = bool(re.search(r"-f\s*\(", cmdline, re.I))
    return backticks > 5 or concat_ops > 3 or format_op


def _has_amsi_bypass(cmdline: str) -> bool:
    patterns = [
        r"amsiutils",
        r"amsiinitfailed",
        r"\[ref\]\.assembly\.gettype",
        r"system\.management\.automation\.amsi",
    ]
    return any(re.search(p, cmdline, re.I) for p in patterns)


def _has_credential_access(cmdline: str) -> bool:
    patterns = [
        r"mimikatz",
        r"invoke-mimikatz",
        r"sekurlsa",
        r"dumpcreds",
        r"lsass",
        r"get-credential.*\|.*export",
    ]
    return any(re.search(p, cmdline, re.I) for p in patterns)


def _has_persistence(cmdline: str) -> bool:
    patterns = [
        r"new-itemproperty.*\\run\\",
        r"register-scheduledtask",
        r"new-service",
        r"wmi.*__eventfilter",
    ]
    return any(re.search(p, cmdline, re.I) for p in patterns)


def _has_defense_evasion(cmdline: str) -> bool:
    patterns = [
        r"-windowstyle\s+hidden",
        r"-noprofile",
        r"-noninteractive",
        r"set-mppreference.*-disablerealtimemonitoring",
        r"clear-eventlog",
        r"remove-item.*\.evtx",
    ]
    return any(re.search(p, cmdline, re.I) for p in patterns)


def try_decode_base64(cmdline: str):
    """If an encoded command is present, attempt to decode it for the audit log."""
    match = re.search(r"-(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]{20,})", cmdline, re.I)
    if not match:
        return None
    try:
        raw = base64.b64decode(match.group(1))
        return raw.decode("utf-16-le", errors="ignore")[:300]
    except Exception:
        return None


RULES = [
    {
        "name": "Base64 Encoded Command",
        "technique": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "severity": "high",
        "matcher": _has_encoded_command,
    },
    {
        "name": "Remote Download Cradle",
        "technique": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "severity": "high",
        "matcher": _has_download_cradle,
    },
    {
        "name": "Script Obfuscation",
        "technique": "T1027.005",
        "technique_name": "Indicator Removal from Tools",
        "tactic": "Defense Evasion",
        "severity": "medium",
        "matcher": _has_obfuscation,
    },
    {
        "name": "AMSI Bypass Attempt",
        "technique": "T1562.001",
        "technique_name": "Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "severity": "critical",
        "matcher": _has_amsi_bypass,
    },
    {
        "name": "Credential Access Tooling",
        "technique": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "severity": "critical",
        "matcher": _has_credential_access,
    },
    {
        "name": "Persistence Mechanism",
        "technique": "T1053/T1547",
        "technique_name": "Scheduled Task / Registry Run Keys",
        "tactic": "Persistence",
        "severity": "high",
        "matcher": _has_persistence,
    },
    {
        "name": "Defense Evasion Flags",
        "technique": "T1562",
        "technique_name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "severity": "medium",
        "matcher": _has_defense_evasion,
    },
]

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def analyze_event(event: dict) -> dict:
    """
    Runs all detection rules against a single log event.
    Returns the event enriched with a 'findings' list and 'max_severity'.
    """
    cmdline = event.get("script_block") or event.get("command_line") or ""
    findings = []

    for rule in RULES:
        if rule["matcher"](cmdline):
            findings.append({
                "rule": rule["name"],
                "mitre_technique": rule["technique"],
                "mitre_technique_name": rule["technique_name"],
                "mitre_tactic": rule["tactic"],
                "severity": rule["severity"],
            })

    max_severity = "none"
    if findings:
        max_severity = max(findings, key=lambda f: SEVERITY_RANK[f["severity"]])["severity"]

    decoded = try_decode_base64(cmdline)

    result = dict(event)
    result["findings"] = findings
    result["max_severity"] = max_severity
    result["is_malicious"] = len(findings) > 0
    if decoded:
        result["decoded_payload_preview"] = decoded
    result["analyzed_at"] = datetime.now(timezone.utc).isoformat()
    return result


def analyze_batch(events: list) -> list:
    return [analyze_event(e) for e in events]
