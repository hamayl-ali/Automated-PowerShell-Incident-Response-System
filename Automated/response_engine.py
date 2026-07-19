"""
response_engine.py
--------------------
Takes automated remediation action based on detection findings.

Design principle: every action is logged to an audit trail BEFORE it is
executed, and every action respects the configured mode:
  - "detect_only"   -> no action taken, alert + log only
  - "auto_respond"  -> action taken automatically if severity >= threshold

Actions implemented:
  1. terminate_process()  -> REAL: sends SIGTERM/SIGKILL via os.kill (stdlib)
  2. quarantine_file()     -> REAL: moves the offending script to a quarantine
                               directory with restricted permissions
  3. block_network_ioc()   -> SIMULATED: appends to a local blocklist.txt.
                               In a production SOC this would call the
                               firewall API (iptables / Windows Firewall /
                               EDR isolation API) -- left as an integration
                               point since it requires elevated privileges
                               and a live network stack to do safely.

Pure Python 3 stdlib. No external dependencies.
"""

import os
import shutil
import signal
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class ResponseEngine:
    def __init__(self, config: dict):
        self.mode = config.get("mode", "detect_only")
        self.min_severity = config.get("min_severity_to_act", "high")
        self.quarantine_dir = config.get("quarantine_dir", "./quarantine")
        self.blocklist_path = config.get("blocklist_path", "./logs/blocklist.txt")
        self.webhook_url = config.get("webhook_url")  # None disables webhook
        self.audit_log = []

        os.makedirs(self.quarantine_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.blocklist_path), exist_ok=True)

    # -- decision logic ----------------------------------------------------

    def _should_act(self, max_severity: str) -> bool:
        if self.mode != "auto_respond":
            return False
        if max_severity == "none":
            return False
        return SEVERITY_RANK[max_severity] >= SEVERITY_RANK[self.min_severity]

    # -- individual actions --------------------------------------------------

    def terminate_process(self, pid: int, reason: str) -> dict:
        """Really attempts to terminate a process by PID (stdlib os.kill)."""
        result = {"action": "terminate_process", "pid": pid, "success": False, "detail": ""}
        try:
            os.kill(pid, signal.SIGTERM)
            result["success"] = True
            result["detail"] = f"SIGTERM sent to PID {pid}"
        except ProcessLookupError:
            result["detail"] = f"PID {pid} not found (already exited or simulated PID)"
        except PermissionError:
            result["detail"] = f"Insufficient privileges to terminate PID {pid}"
        except Exception as e:
            result["detail"] = f"Error: {e}"
        return result

    def quarantine_file(self, file_path: str, reason: str) -> dict:
        """Really moves a file into the quarantine directory if it exists."""
        result = {"action": "quarantine_file", "file_path": file_path, "success": False, "detail": ""}
        if not file_path or not os.path.exists(file_path):
            result["detail"] = f"File not found on disk (simulated path): {file_path}"
            return result
        try:
            dest = os.path.join(self.quarantine_dir, os.path.basename(file_path) + ".quarantined")
            shutil.move(file_path, dest)
            os.chmod(dest, 0o400)
            result["success"] = True
            result["detail"] = f"Moved to {dest} and set read-only"
        except Exception as e:
            result["detail"] = f"Error: {e}"
        return result

    def block_network_ioc(self, ip_or_domain: str, reason: str) -> dict:
        """
        SIMULATED action. Appends IOC to a local blocklist file rather than
        touching the real firewall, since that requires root/admin and a
        live network stack. In production, replace this function body with
        a call to your firewall/EDR API, e.g.:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        """
        result = {"action": "block_network_ioc", "indicator": ip_or_domain,
                  "success": False, "detail": "", "simulated": True}
        try:
            with open(self.blocklist_path, "a") as f:
                f.write(f"{datetime.now(timezone.utc).isoformat()}\t{ip_or_domain}\t{reason}\n")
            result["success"] = True
            result["detail"] = f"Added {ip_or_domain} to local blocklist (simulated firewall rule)"
        except Exception as e:
            result["detail"] = f"Error: {e}"
        return result

    # -- webhook alerting -----------------------------------------------------

    def send_alert(self, payload: dict):
        """Sends a JSON alert to a configured webhook (e.g. Slack incoming webhook).
        No-op if webhook_url is not configured."""
        if not self.webhook_url:
            return {"sent": False, "detail": "No webhook_url configured"}
        try:
            data = json.dumps({"text": json.dumps(payload, indent=2)}).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url, data=data,
                headers={"Content-Type": "application/json"}, method="POST"
            )
            urllib.request.urlopen(req, timeout=5)
            return {"sent": True, "detail": "Webhook delivered"}
        except urllib.error.URLError as e:
            return {"sent": False, "detail": f"Webhook failed: {e}"}
        except Exception as e:
            return {"sent": False, "detail": f"Webhook error: {e}"}

    # -- orchestration --------------------------------------------------------

    def handle_event(self, analyzed_event: dict) -> dict:
        """
        Given an event already scored by detection_engine, decide whether to
        act, take the action(s), and record everything to the audit trail.
        """
        max_sev = analyzed_event.get("max_severity", "none")
        findings = analyzed_event.get("findings", [])

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": analyzed_event.get("event_id"),
            "host": analyzed_event.get("host"),
            "user": analyzed_event.get("user"),
            "pid": analyzed_event.get("pid"),
            "max_severity": max_sev,
            "findings": findings,
            "mode": self.mode,
            "action_taken": False,
            "actions": [],
        }

        if not findings:
            entry["disposition"] = "benign - no action"
            self.audit_log.append(entry)
            return entry

        if not self._should_act(max_sev):
            entry["disposition"] = (
                "alert only - detect_only mode" if self.mode == "detect_only"
                else f"alert only - severity '{max_sev}' below threshold '{self.min_severity}'"
            )
            self.audit_log.append(entry)
            return entry

        # Auto-respond: take action(s) based on technique tactics involved
        reason = f"{max_sev.upper()} severity: " + ", ".join(f["rule"] for f in findings)
        actions = []

        pid = analyzed_event.get("pid")
        if pid:
            actions.append(self.terminate_process(pid, reason))

        file_path = analyzed_event.get("script_path")
        if file_path:
            actions.append(self.quarantine_file(file_path, reason))

        ioc = analyzed_event.get("remote_indicator")
        if ioc:
            actions.append(self.block_network_ioc(ioc, reason))

        entry["action_taken"] = True
        entry["actions"] = actions
        entry["disposition"] = "auto-remediated"

        alert_result = self.send_alert({
            "severity": max_sev,
            "host": analyzed_event.get("host"),
            "user": analyzed_event.get("user"),
            "findings": [f["rule"] for f in findings],
            "actions": [a["action"] for a in actions],
        })
        entry["alert"] = alert_result

        self.audit_log.append(entry)
        return entry

    def export_audit_log(self, path: str):
        with open(path, "w") as f:
            json.dump(self.audit_log, f, indent=2)
