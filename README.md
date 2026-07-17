# 🛡️ Automated PowerShell Incident Response System

> **A SOAR-inspired automated incident response system that detects malicious PowerShell activity and automatically responds based on configurable severity thresholds.**

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Cross--Platform-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## 📌 Overview

Traditional Security Operations Centers (SOCs) detect suspicious PowerShell activity but still rely on analysts to manually investigate and respond.

This project bridges that gap by combining:

- 🔍 Signature-based detection
- ⚡ Automated response
- 📊 Audit logging
- 🛡️ Configurable safety controls

The result is a lightweight **SOAR-style (Security Orchestration, Automation and Response)** pipeline capable of detecting, scoring, and responding to PowerShell-based attacks automatically.

---

# ✨ Features

- Detects malicious PowerShell activity
- MITRE ATT&CK mapped detection rules
- Automatic process termination
- File quarantine
- Simulated network IOC blocking
- Configurable severity thresholds
- Detect-only mode
- Auto-response mode
- Detailed audit logging
- Incident report generation
- Optional Slack webhook integration
- Zero external Python dependencies

---

# 🏗️ Architecture

```
PowerShell Events
        │
        ▼
Detection Engine
        │
        ▼
Severity Scoring
        │
        ▼
Decision Engine
        │
        ├──────── Detect Only
        │             │
        │             ▼
        │        Alert + Log
        │
        └──────── Auto Respond
                      │
      ┌───────────────┼────────────────┐
      ▼               ▼                ▼
Terminate      Quarantine File   Block IOC
      │               │                │
      └───────────────┼────────────────┘
                      ▼
             Audit Logs & Reports
```

---

# 🎯 Detection Rules

| Rule | MITRE ATT&CK | Severity |
|------|--------------|----------|
| Base64 Encoded Commands | T1027 | High |
| Download Cradle | T1105 | High |
| Script Obfuscation | T1027.005 | Medium |
| AMSI Bypass | T1562.001 | Critical |
| Credential Dumping | T1003 | Critical |
| Persistence | T1053 / T1547 | High |
| Defense Evasion | T1562 | Medium |

---

# 📂 Project Structure

```
.
├── detection_engine.py
├── response_engine.py
├── incident_response.py
├── sample_data/
│   ├── powershell_events.json
│   └── malware_samples/
├── quarantine/
├── logs/
```

---

# 🚀 Getting Started

## Clone Repository

```bash
git clone https://github.com/hamayl-ali/Automated-PowerShell-Incident-Response-System.git

cd Automated-PowerShell-Incident-Response-System
```

---

## Detect Only Mode

```bash
python3 incident_response.py \
--input sample_data/powershell_events.json \
--mode detect_only
```

---

## Auto Response Mode

```bash
python3 incident_response.py \
--input sample_data/powershell_events.json \
--mode auto_respond
```

---

## Using Configuration File

```bash
python3 incident_response.py \
--input sample_data/powershell_events.json \
--config config.json
```

---

# ⚙️ Configuration

```json
{
  "mode": "auto_respond",
  "min_severity_to_act": "high",
  "quarantine_dir": "./quarantine",
  "blocklist_path": "./logs/blocklist.txt",
  "webhook_url": null
}
```

---

# 📊 Output

The system automatically generates:

```
logs/
├── audit_log_<timestamp>.json
├── incident_report_<timestamp>.csv
└── blocklist.txt
```

---

# 🛡️ Security Design

The response engine follows a **safe-by-default** philosophy.

✔ Detect-only mode never modifies the system.

✔ Auto-response only executes when:

- Severity exceeds configured threshold
- Auto-response mode is enabled

This minimizes false positives while enabling rapid containment.

---

# 🧰 Tech Stack

- Python 3
- Regular Expressions
- JSON
- CSV
- Base64
- OS & Signal Modules
- shutil
- urllib
- argparse

No third-party libraries required.

---

# 📈 Future Improvements

- Windows Event Log (4104) ingestion
- Live Sysmon integration
- Sigma rule support
- YARA integration
- Firewall automation
- Slack & Microsoft Teams formatting
- Flask/FastAPI Dashboard
- SIEM integration (Splunk, Wazuh, Elastic)

---

# 📸 Sample Workflow

```
PowerShell Execution
        ↓
Detection Rules Trigger
        ↓
Severity Calculated
        ↓
Decision Engine
        ↓
Auto Containment
        ↓
Audit Logging
        ↓
Incident Report
```

---

# 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Open a Pull Request

---

# 📜 License

This project is released under the MIT License.

---

# 👨‍💻 Author

**Hamayl**

BS Computer Science | Cybersecurity Enthusiast

Interested in:

- Incident Response
- Threat Detection
- SOAR
- Malware Analysis
- Machine Learning for Security

⭐ If you found this project useful, consider giving it a star!
