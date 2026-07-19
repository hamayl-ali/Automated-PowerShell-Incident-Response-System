# Automated PowerShell Incident Response System

A detection-and-response engine that doesn't just flag suspicious PowerShell
activity — it automatically contains it. Built as an extension to a
signature-based detector, adding the automation layer that separates SOC
monitoring from security engineering.

## Problem Statement

Traditional SOC tooling detects malicious PowerShell activity and raises an
alert, but a human analyst still has to triage, investigate, and manually
respond — often minutes or hours later. In fast-moving incidents (credential
dumping, AMSI bypass, C2 download cradles), that delay is the difference
between a contained incident and a full compromise.

This project closes that gap with a **SOAR-style (Security Orchestration,
Automation, and Response) pipeline**: detect → score → decide → act → log,
all in a single automated pass, with safety controls so it never acts
recklessly.

## Architecture

```
                    ┌─────────────────────┐
                    │  PowerShell / 4104   │
                    │  Log Events (JSON)   │
                    └──────────┬───────────┘
                               │
                               ▼
                  ┌─────────────────────────┐
                  │   detection_engine.py    │
                  │  7 MITRE-mapped rules:   │
                  │  encoding, obfuscation,  │
                  │  AMSI bypass, cred theft,│
                  │  persistence, C2, evasion│
                  └──────────┬──────────────┘
                             │  scored event
                             │  (severity + findings)
                             ▼
                  ┌─────────────────────────┐
                  │   response_engine.py     │
                  │                          │
                  │  mode == detect_only?    │───► alert + log only
                  │  severity >= threshold?  │
                  └──────────┬──────────────┘
                             │ yes → auto_respond
                             ▼
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                     ▼
 terminate_process()  quarantine_file()   block_network_ioc()
   (real: os.kill)    (real: move + lock)  (simulated: blocklist,
                                             documented firewall
                                             integration point)
        │                    │                     │
        └────────────────────┼─────────────────────┘
                             ▼
                  ┌─────────────────────────┐
                  │  Audit Trail + Webhook   │
                  │  audit_log.json (full)   │
                  │  incident_report.csv     │
                  │  optional Slack webhook  │
                  └─────────────────────────┘
```

## Key Design Decisions

**Every action is gated by mode and severity threshold.** The engine never
auto-remediates in `detect_only` mode, and even in `auto_respond` mode it
respects a configurable `min_severity_to_act` — a medium-severity finding
gets logged and alerted, not acted on, reflecting real SOC caution around
false positives.

**Actions are real where it's safe to demonstrate, simulated where it isn't.**
- `terminate_process()` genuinely calls `os.kill()` on the given PID.
- `quarantine_file()` genuinely moves the offending script to an isolated,
  read-only directory.
- `block_network_ioc()` is intentionally simulated (appends to a local
  blocklist file) since a real firewall rule requires root/admin privileges
  and a live network stack — the integration point for `iptables` or a
  Windows Firewall / EDR isolation API call is documented directly in the
  function docstring.

**Every disposition is logged, not just the actions.** Benign events, alert-
only events, and auto-remediated events all get an audit trail entry — this
is what a compliance reviewer or hiring manager would expect from a real
incident response system.

## MITRE ATT&CK Coverage

| Rule | Technique | Tactic | Severity |
|---|---|---|---|
| Base64 Encoded Command | T1027 | Defense Evasion | High |
| Remote Download Cradle | T1105 | Command and Control | High |
| Script Obfuscation | T1027.005 | Defense Evasion | Medium |
| AMSI Bypass Attempt | T1562.001 | Defense Evasion | Critical |
| Credential Access Tooling | T1003 | Credential Access | Critical |
| Persistence Mechanism | T1053 / T1547 | Persistence | High |
| Defense Evasion Flags | T1562 | Defense Evasion | Medium |

## Usage

```bash
# Detect-only mode (alert + log, no remediation)
python3 incident_response.py --input sample_data/powershell_events.json --mode detect_only

# Auto-respond mode (real quarantine + termination attempt + simulated block)
python3 incident_response.py --input sample_data/powershell_events.json --mode auto_respond

# Use config.json defaults instead of a CLI override
python3 incident_response.py --input sample_data/powershell_events.json --config config.json
```

Output is written to `logs/`:
- `audit_log_<timestamp>.json` — full detail per event (findings, actions, timestamps)
- `incident_report_<timestamp>.csv` — recruiter/analyst-friendly summary table

## Configuration (`config.json`)

```json
{
  "mode": "auto_respond",          // or "detect_only"
  "min_severity_to_act": "high",   // low | medium | high | critical
  "quarantine_dir": "./quarantine",
  "blocklist_path": "./logs/blocklist.txt",
  "webhook_url": null              // set to a Slack incoming webhook URL to enable alerts
}
```

## Sample Data

`sample_data/powershell_events.json` contains 10 synthetic events: 5 benign
(routine admin commands) and 5 malicious, covering encoded commands, download
cradles, AMSI bypass, credential dumping, and persistence. The referenced
"malicious" script files under `sample_data/malware_samples/` are harmless
placeholder text files — safe to run and inspect, they exist only so the
quarantine action has something real to move.

## Tech Stack

Python 3 standard library only (`re`, `base64`, `os`, `shutil`, `signal`,
`json`, `urllib`, `argparse`, `csv`) — no external dependencies, runs
anywhere Python 3 is installed.

## Possible Extensions

- Real firewall integration (`iptables` / Windows Firewall / EDR isolation API)
  in place of the simulated `block_network_ioc()`
- Ingest live Windows Event Log (4104/4688) via `pywin32` instead of static JSON
- Slack/Teams webhook formatting instead of raw JSON payload
- Web dashboard (Flask/FastAPI) to visualize the audit trail in real time
