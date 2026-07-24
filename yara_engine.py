"""
yara_engine.py
----------------
Compiles and runs YARA rules against PowerShell command text (including any
decoded base64 payload) and against quarantined files on disk.

Requires yara-python: pip install yara-python --break-system-packages
"""

import os

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


def compile_rules(rules_dir: str):
    """Compiles every .yar/.yara file in a directory into a single ruleset.
    Returns None if yara-python isn't installed or no rule files are found --
    callers should treat that as "YARA scanning disabled", not an error."""
    if not YARA_AVAILABLE or not rules_dir or not os.path.isdir(rules_dir):
        return None
    rule_files = {}
    for fn in sorted(os.listdir(rules_dir)):
        if fn.endswith((".yar", ".yara")):
            name = os.path.splitext(fn)[0]
            rule_files[name] = os.path.join(rules_dir, fn)
    if not rule_files:
        return None
    try:
        return yara.compile(filepaths=rule_files)
    except Exception:
        return None


def _format_matches(matches) -> list:
    findings = []
    for m in matches:
        meta = dict(m.meta) if hasattr(m, "meta") else {}
        findings.append({
            "rule": m.rule,
            "severity": meta.get("severity", "medium"),
            "mitre_technique": meta.get("mitre", "N/A"),
            "source": "yara",
            "description": meta.get("description", ""),
            "matched_strings": [s.identifier for s in m.strings] if hasattr(m, "strings") else [],
        })
    return findings


def scan_text(compiled_rules, text: str) -> list:
    if not compiled_rules or not text:
        return []
    try:
        matches = compiled_rules.match(data=text.encode("utf-8", errors="ignore"))
        return _format_matches(matches)
    except Exception:
        return []


def scan_file(compiled_rules, filepath: str) -> list:
    if not compiled_rules or not filepath or not os.path.exists(filepath):
        return []
    try:
        matches = compiled_rules.match(filepath)
        return _format_matches(matches)
    except Exception:
        return []
