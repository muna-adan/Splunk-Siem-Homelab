#!/usr/bin/env python3
"""
deploy_alerts.py — Splunk Alert Deployment Script
==================================================
Deploys all 7 homelab detection rules to Splunk as saved searches
via the Splunk REST API. Replaces existing alerts of the same name
so it's safe to run multiple times.
 

 
Usage:
    python deploy_alerts.py              # Deploy all alerts
    python deploy_alerts.py --list       # List alerts without deploying
    python deploy_alerts.py --delete     # Delete all homelab alerts
    python deploy_alerts.py --verify     # Check which alerts exist in Splunk
 
Requirements:
    pip install requests python-dotenv
 
Setup:
    Create a .env file next to this script:
        SPLUNK_PASSWORD=your_splunk_password
 
    Or just set SPLUNK_PASS directly below.
"""
 
import requests
import json
import argparse
import os
import sys
import urllib3
from datetime import datetime
from dotenv import load_dotenv
 
load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
 
# ── Configuration ─────────────────────────────────────────────
# Change these to match your Splunk install
SPLUNK_HOST  = "https://localhost:8089"   # Default Splunk management port
SPLUNK_USER  = "muna"   # change this to your Splunk username
SPLUNK_PASS  = os.getenv("SPLUNK_PASSWORD", "changeme")
SPLUNK_APP   = "search"                   # The Splunk app to save alerts in
SPLUNK_OWNER = "muna"   # change this to your Splunk username
 
# Base URL for saved searches API
SAVED_SEARCHES_URL = (
    f"{SPLUNK_HOST}/servicesNS/nobody/{SPLUNK_APP}/saved/searches"
)
 
# ── ANSI colors ───────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
 
 
# ══════════════════════════════════════════════════════════════
# ALERT DEFINITIONS
# Each dict defines one Splunk saved search / scheduled alert.
#
# Fields:
#   name          — what appears in Splunk's Alerts UI
#   description   — documents what this alert detects
#   technique     — MITRE ATT&CK ID
#   spl           — the Splunk search query (SPL)
#   cron          — cron schedule (*/5 = every 5 minutes)
#   threshold     — how many results trigger the alert
#   severity      — critical / high / medium / low / informational
# ══════════════════════════════════════════════════════════════
 
ALERTS = [
 
    # ════════════════════════════════════════════════════════
    # ORIGINAL RULES — Built during initial homelab setup
    # These use sourcetype= matching your actual Splunk inputs
    # ════════════════════════════════════════════════════════
 
    # ── Original Rule 1: SSH Brute Force (Linux) ──────────
    {
        "name": "HOMELAB - SSH Brute Force Detected",
        "description": "T1110.001 | Detects failed SSH login attempts exceeding 5 from any host within 5 minutes.",
        "technique": "T1110.001",
        "spl": (
            'index=main sourcetype=linux_secure "Failed password" '
            '| stats count by host '
            '| where count > 5'
        ),
        "cron": "*/5 * * * *",
        "threshold": "1",
        "severity": "high",
    },
 
    # ── Original Rule 2: Failed Windows Logins (4625) ─────
    {
        "name": "HOMELAB - Brute Force Failed Windows Logins",
        "description": "T1110.001 | Detects repeated failed Windows logon attempts exceeding 3 per account within 5 minutes.",
        "technique": "T1110.001",
        "spl": (
            'index=main sourcetype=WinEventLog EventCode=4625 '
            '| stats count by Account_Name, host '
            '| where count > 3'
        ),
        "cron": "*/5 * * * *",
        "threshold": "1",
        "severity": "high",
    },
 
    # ── Original Rule 3: New User Account Created (4720) ──
    {
        "name": "HOMELAB - New User Account Created",
        "description": "T1136 | Detects creation of new Windows user accounts (Event ID 4720). Any new account should be investigated.",
        "technique": "T1136",
        "spl": (
            'index=main sourcetype=WinEventLog EventCode=4720'
        ),
        "cron": "*/5 * * * *",
        "threshold": "1",
        "severity": "medium",
    },
 
    # ════════════════════════════════════════════════════════
    # EXPANDED RULES — Phase 1 detection engineering additions
    # ════════════════════════════════════════════════════════
 
    # ── Expanded Rule 1: Password Spraying ────────────────
    {
        "name": "HOMELAB - Password Spraying Detected",
        "description": "T1110.003 | Detects one source IP targeting >3 different usernames in 5 minutes — distinct from brute force.",
        "technique": "T1110.003",
        "spl": (
            'index=main sourcetype=linux_secure "Failed password" '
            '| rex field=_raw "for (?:invalid user )?(?P<username>\\S+) from (?P<src_ip>\\S+)" '
            '| bucket _time span=5m '
            '| stats dc(username) as unique_users count as attempts by src_ip _time '
            '| where unique_users > 3 AND attempts > 10'
        ),
        "cron": "*/5 * * * *",
        "threshold": "1",
        "severity": "high",
    },
 
    # ── Expanded Rule 2: Scheduled Task Created (4698) ────
    {
        "name": "HOMELAB - Scheduled Task Created",
        "description": "T1053.005 | Detects Windows Security Event 4698 — scheduled task creation used for persistence.",
        "technique": "T1053.005",
        "spl": (
            'index=main sourcetype=WinEventLog EventCode=4698 '
            '| table _time src_user TaskName TaskContent'
        ),
        "cron": "*/5 * * * *",
        "threshold": "1",
        "severity": "medium",
    },
 
    # ── Expanded Rule 3: Windows Event Logs Cleared ───────
    {
        "name": "HOMELAB - Windows Event Logs Cleared",
        "description": "T1070.001 | Detects Security Event 1102 or System Event 104 — log clearing used to evade detection.",
        "technique": "T1070.001",
        "spl": (
            'index=main sourcetype=WinEventLog '
            '(EventCode=1102 OR EventCode=104) '
            '| table _time src_user Message'
        ),
        "cron": "*/5 * * * *",
        "threshold": "1",
        "severity": "high",
    },
 
    # ── Expanded Rule 4: Valid Account New Admin (4720) ───
    {
        "name": "HOMELAB - New Admin Account Persistence",
        "description": "T1078 | Detects new local admin account creation with detailed user/host context for persistence investigation.",
        "technique": "T1078",
        "spl": (
            'index=main sourcetype=WinEventLog EventCode=4720 '
            '| table _time src_user user dest'
        ),
        "cron": "*/5 * * * *",
        "threshold": "1",
        "severity": "medium",
    },
]
 
 
# ══════════════════════════════════════════════════════════════
# CORE API FUNCTIONS
# ══════════════════════════════════════════════════════════════
 
def test_connection() -> bool:
    """
    Verify we can reach Splunk before doing anything else.
    Returns True if connection succeeds, False otherwise.
    """
    try:
        r = requests.get(
            f"{SPLUNK_HOST}/services/server/info",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            verify=False,
            timeout=10,
            params={"output_mode": "json"}
        )
        if r.status_code == 200:
            info = r.json().get("entry", [{}])[0].get("content", {})
            version = info.get("version", "unknown")
            print(f"{GREEN}[✓] Connected to Splunk {version} at {SPLUNK_HOST}{RESET}")
            return True
        elif r.status_code == 401:
            print(f"{RED}[✗] Authentication failed. Check SPLUNK_PASS in your .env file.{RESET}")
        else:
            print(f"{RED}[✗] Unexpected response: HTTP {r.status_code}{RESET}")
        return False
    except requests.exceptions.ConnectionError:
        print(f"{RED}[✗] Cannot connect to {SPLUNK_HOST}")
        print(f"    Is Splunk running? Try: sudo systemctl status splunkd{RESET}")
        return False
    except Exception as e:
        print(f"{RED}[✗] Connection error: {e}{RESET}")
        return False
 
 
def alert_exists(name: str) -> bool:
    """Check if a saved search with this name already exists in Splunk."""
    try:
        r = requests.get(
            f"{SAVED_SEARCHES_URL}/{requests.utils.quote(name, safe='')}",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            verify=False,
            timeout=10,
            params={"output_mode": "json"}
        )
        return r.status_code == 200
    except Exception:
        return False
 
 
def delete_alert(name: str) -> bool:
    """Delete a saved search by name."""
    try:
        r = requests.delete(
            f"{SAVED_SEARCHES_URL}/{requests.utils.quote(name, safe='')}",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            verify=False,
            timeout=10
        )
        return r.status_code in (200, 201)
    except Exception:
        return False
 
 
def deploy_alert(alert: dict) -> bool:
    """
    Deploy a single alert to Splunk.
 
    The Splunk saved search API accepts these key fields:
      search              — the SPL query
      cron_schedule       — when to run it
      is_scheduled        — 1 to enable scheduling
      alert_type          — "number of events" triggers when result count matches
      alert_comparator    — "greater than" threshold comparison
      alert_threshold     — minimum result count to trigger
      alert.severity      — severity level shown in Splunk UI
      alert.suppress      — 0 means don't suppress duplicate alerts
      disabled            — 0 means alert is active
    """
    # If it already exists, delete it first so we can redeploy cleanly
    if alert_exists(alert["name"]):
        delete_alert(alert["name"])
 
    payload = {
        "name":               alert["name"],
        "search":             alert["spl"],
        "description":        alert["description"],
        "cron_schedule":      alert["cron"],
        "is_scheduled":       "1",
        "alert_type":         "number of events",
        "alert_comparator":   "greater than",
        "alert_threshold":    alert["threshold"],
        "alert.severity":     str({"critical":"1","high":"2","medium":"3","low":"4"}.get(alert["severity"], "2")),
        "alert.suppress":     "0",
        "alert.track":        "1",
        "dispatch.earliest_time": "-5m",
        "dispatch.latest_time":   "now",
        "disabled":           "0",
        "output_mode":        "json",
    }
 
    try:
        r = requests.post(
            SAVED_SEARCHES_URL,
            auth=(SPLUNK_USER, SPLUNK_PASS),
            verify=False,
            data=payload,
            timeout=15
        )
        if r.status_code in (200, 201):
            return True
        else:
            # Print the error detail from Splunk so you know exactly what went wrong
            try:
                msg = r.json().get("messages", [{}])[0].get("text", r.text[:200])
            except Exception:
                msg = r.text[:200]
            print(f"     {RED}Splunk error: {msg}{RESET}")
            return False
    except Exception as e:
        print(f"     {RED}Request error: {e}{RESET}")
        return False
 
 
# ══════════════════════════════════════════════════════════════
# CLI ACTIONS
# ══════════════════════════════════════════════════════════════
 
def action_deploy():
    """Deploy all alerts to Splunk."""
    print(f"\n{BOLD}Deploying {len(ALERTS)} alerts to Splunk...{RESET}\n")
    passed = 0
    failed = 0
 
    for alert in ALERTS:
        ok = deploy_alert(alert)
        if ok:
            print(f"  {GREEN}[✓]{RESET} {alert['name']}")
            passed += 1
        else:
            print(f"  {RED}[✗]{RESET} {alert['name']}")
            failed += 1
 
    print(f"\n{BOLD}{'─'*50}")
    print(f"  Deployed: {passed}/{len(ALERTS)}  |  Failed: {failed}")
    print(f"{'─'*50}{RESET}")
    if passed > 0:
        print(f"\n  {GREEN}View in Splunk:{RESET} Settings → Searches, reports, and alerts")
        print(f"  Or go to:       Activity → Triggered Alerts\n")
 
 
def action_list():
    """Print all alerts that would be deployed without actually doing it."""
    print(f"\n{BOLD}Alerts defined in deploy_alerts.py:{RESET}\n")
    for i, alert in enumerate(ALERTS, 1):
        print(f"  {i}. {BOLD}{alert['name']}{RESET}")
        print(f"     Technique : {alert['technique']}")
        print(f"     Severity  : {alert['severity']}")
        print(f"     Schedule  : {alert['cron']}  (every 5 min)")
        print(f"     Threshold : triggers when results > {alert['threshold']}")
        print()
 
 
def action_verify():
    """Check which alerts exist in Splunk right now."""
    print(f"\n{BOLD}Checking Splunk for homelab alerts...{RESET}\n")
    found = 0
    for alert in ALERTS:
        exists = alert_exists(alert["name"])
        status = f"{GREEN}EXISTS{RESET}" if exists else f"{YELLOW}MISSING{RESET}"
        print(f"  [{status}] {alert['name']}")
        if exists:
            found += 1
    print(f"\n  {found}/{len(ALERTS)} alerts found in Splunk.\n")
 
 
def action_delete():
    """Delete all homelab alerts from Splunk."""
    confirm = input(
        f"\n{YELLOW}Delete all {len(ALERTS)} homelab alerts from Splunk? (yes/no): {RESET}"
    ).strip().lower()
    if confirm != "yes":
        print("Cancelled.")
        return
 
    print()
    deleted = 0
    for alert in ALERTS:
        if alert_exists(alert["name"]):
            ok = delete_alert(alert["name"])
            if ok:
                print(f"  {GREEN}[✓]{RESET} Deleted: {alert['name']}")
                deleted += 1
            else:
                print(f"  {RED}[✗]{RESET} Failed: {alert['name']}")
        else:
            print(f"  {GRAY}[–]{RESET} Not found: {alert['name']}")
    print(f"\n  Deleted {deleted} alert(s).\n")
 
 
# ══════════════════════════════════════════════════════════════
# ENTRYPOINT
# ══════════════════════════════════════════════════════════════
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Deploy detection alerts to Splunk SIEM"
    )
    parser.add_argument(
        "--list",   action="store_true", help="List all alerts without deploying"
    )
    parser.add_argument(
        "--verify", action="store_true", help="Check which alerts exist in Splunk"
    )
    parser.add_argument(
        "--delete", action="store_true", help="Delete all homelab alerts from Splunk"
    )
    args = parser.parse_args()
 
    # Always test connection first (except for --list which doesn't need Splunk)
    if not args.list:
        print(f"\n{BOLD}Testing Splunk connection...{RESET}")
        if not test_connection():
            sys.exit(1)
 
    if args.list:
        action_list()
    elif args.verify:
        action_verify()
    elif args.delete:
        action_delete()
    else:
        action_deploy()

