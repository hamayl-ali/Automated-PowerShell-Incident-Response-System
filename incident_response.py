#!/usr/bin/env python3
"""
incident_response.py
----------------------
Automated PowerShell Incident Response System.

Pipeline:
    1. Load PowerShell/process-creation log events (JSON)
    2. Run detection_engine to score each event against:
         - built-in MITRE-mapped regex rules
         - Sigma rules (sigma_rules/) via sigma_engine.py
         - YARA rules (yara_rules/) via yara_engine.py
    3. Run response_engine to decide + execute remediation actions
       (respecting the configured mode: detect_only vs auto_respond)
    4. Write a full audit trail (JSON) and a summary report (CSV)

Usage:
    python3 incident_response.py --input sample_data/powershell_events.json --config config.json
    python3 incident_response.py --input sample_data/powershell_events.json --mode detect_only
    python3 incident_response.py --input sample_data/powershell_events.json --no-sigma --no-yara

Pure Python 3 stdlib for the core pipeline. Sigma support needs PyYAML;
YARA support needs yara-python. Both degrade gracefully (skipped, not a
crash) if their rule directory is empty or the library isn't installed.
"""

import argparse
import json
import csv
import os
import sys
from datetime import datetime, timezone

from detection_engine import analyze_batch
from response_engine import ResponseEngine
from sigma_engine import load_sigma_rules
from yara_engine import compile_rules as compile_yara_rules, YARA_AVAILABLE


def load_events(path: str) -> list:
    with open(path, "r") as f:
        return json.load(f)


def load_config(path: str) -> dict:
    if not os.path.exists(path):
        return {"mode": "detect_only", "min_severity_to_act": "high",
                "quarantine_dir": "./quarantine", "blocklist_path": "./logs/blocklist.txt",
                "webhook_url": None}
    with open(path, "r") as f:
        return json.load(f)


def write_csv_report(entries: list, path: str):
    fieldnames = [
        "timestamp", "event_id", "host", "user", "pid", "max_severity",
        "mitre_techniques", "detection_sources", "disposition", "action_taken", "actions_summary",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for e in entries:
            techniques = ", ".join(sorted(set(
                f["mitre_technique"] for f in e.get("findings", [])
            )))
            sources = ", ".join(sorted(set(
                f.get("source", "regex") for f in e.get("findings", [])
            )))
            actions_summary = "; ".join(
                f"{a['action']}({'ok' if a['success'] else 'failed'})"
                for a in e.get("actions", [])
            )
            writer.writerow({
                "timestamp": e["timestamp"],
                "event_id": e.get("event_id"),
                "host": e.get("host"),
                "user": e.get("user"),
                "pid": e.get("pid"),
                "max_severity": e.get("max_severity"),
                "mitre_techniques": techniques,
                "detection_sources": sources,
                "disposition": e.get("disposition"),
                "action_taken": e.get("action_taken"),
                "actions_summary": actions_summary,
            })


def print_summary(entries: list):
    total = len(entries)
    malicious = sum(1 for e in entries if e.get("findings"))
    acted = sum(1 for e in entries if e.get("action_taken"))
    by_sev = {}
    for e in entries:
        sev = e.get("max_severity", "none")
        by_sev[sev] = by_sev.get(sev, 0) + 1

    print("\n" + "=" * 60)
    print("AUTOMATED INCIDENT RESPONSE - RUN SUMMARY")
    print("=" * 60)
    print(f"Events processed:     {total}")
    print(f"Malicious findings:   {malicious}")
    print(f"Auto-remediated:      {acted}")
    print("Severity breakdown:")
    for sev in ["critical", "high", "medium", "low", "none"]:
        if sev in by_sev:
            print(f"  {sev:<10} {by_sev[sev]}")
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Automated PowerShell Incident Response System")
    parser.add_argument("--input", required=True, help="Path to JSON log events file")
    parser.add_argument("--config", default="config.json", help="Path to config JSON")
    parser.add_argument("--mode", choices=["detect_only", "auto_respond"],
                         help="Override mode from config file")
    parser.add_argument("--output-dir", default="logs", help="Directory for audit/report output")
    parser.add_argument("--sigma-dir", default="sigma_rules", help="Directory of Sigma rule YAML files")
    parser.add_argument("--yara-dir", default="yara_rules", help="Directory of YARA rule files")
    parser.add_argument("--no-sigma", action="store_true", help="Disable Sigma rule evaluation")
    parser.add_argument("--no-yara", action="store_true", help="Disable YARA rule evaluation")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    events = load_events(args.input)
    config = load_config(args.config)
    if args.mode:
        config["mode"] = args.mode

    print(f"[+] Loaded {len(events)} events from {args.input}")
    print(f"[+] Response mode: {config['mode']}  |  Min severity to act: {config['min_severity_to_act']}")

    sigma_rules = None
    if not args.no_sigma:
        sigma_rules = load_sigma_rules(args.sigma_dir)
        print(f"[+] Loaded {len(sigma_rules)} Sigma rule(s) from {args.sigma_dir}")

    yara_rules = None
    if not args.no_yara:
        if not YARA_AVAILABLE:
            print("[!] yara-python not installed -- skipping YARA scanning "
                  "(pip install yara-python --break-system-packages)")
        else:
            yara_rules = compile_yara_rules(args.yara_dir)
            print(f"[+] YARA rules compiled from {args.yara_dir}: "
                  f"{'enabled' if yara_rules else 'none found, skipping'}")

    analyzed = analyze_batch(events, sigma_rules=sigma_rules, yara_rules=yara_rules)

    engine = ResponseEngine(config)
    processed_entries = [engine.handle_event(e) for e in analyzed]

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = os.path.join(args.output_dir, f"audit_log_{ts}.json")
    csv_path = os.path.join(args.output_dir, f"incident_report_{ts}.csv")

    engine.export_audit_log(json_path)
    write_csv_report(processed_entries, csv_path)

    print_summary(processed_entries)
    print(f"[+] Full audit trail (JSON): {json_path}")
    print(f"[+] Summary report (CSV):    {csv_path}")


if __name__ == "__main__":
    main()
