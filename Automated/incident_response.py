#!/usr/bin/env python3
"""
incident_response.py
----------------------
Automated PowerShell Incident Response System.

Pipeline:
    1. Load PowerShell/process-creation log events (JSON)
    2. Run detection_engine to score each event against MITRE-mapped rules
    3. Run response_engine to decide + execute remediation actions
       (respecting the configured mode: detect_only vs auto_respond)
    4. Write a full audit trail (JSON) and a summary report (CSV)

Usage:
    python3 incident_response.py --input sample_data/powershell_events.json --config config.json
    python3 incident_response.py --input sample_data/powershell_events.json --mode detect_only

Pure Python 3 stdlib. No external dependencies required.
"""

import argparse
import json
import csv
import os
import sys
from datetime import datetime, timezone

from detection_engine import analyze_batch
from response_engine import ResponseEngine


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
        "mitre_techniques", "disposition", "action_taken", "actions_summary",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for e in entries:
            techniques = ", ".join(sorted(set(
                f["mitre_technique"] for f in e.get("findings", [])
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
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    events = load_events(args.input)
    config = load_config(args.config)
    if args.mode:
        config["mode"] = args.mode

    print(f"[+] Loaded {len(events)} events from {args.input}")
    print(f"[+] Response mode: {config['mode']}  |  Min severity to act: {config['min_severity_to_act']}")

    analyzed = analyze_batch(events)

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
