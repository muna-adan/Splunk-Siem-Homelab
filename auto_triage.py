#!/usr/bin/env python3
"""
auto_triage.py — Automated Alert Triage & Enrichment
=====================================================
Polls Splunk for new security alerts, enriches each source IP
with AbuseIPDB threat intel, makes a triage decision, and logs
everything to a structured case file.
 
This is the same logic SOAR platforms (Splunk SOAR, Palo Alto XSOAR)
use under the hood — you're building it from scratch.
 
Usage:
    python auto_triage.py              # Run once, triage all recent alerts
    python auto_triage.py --watch      # Poll every 60s continuously
    python auto_triage.py --summary    # Print case log summary
 
Requirements:
    pip install requests python-dotenv
 
Setup:
    1. Create a .env file with:
       SPLUNK_PASSWORD=your_splunk_password
       ABUSEIPDB_KEY=your_free_api_key   # Free at abuseipdb.com
    2. Run: python auto_triage.py
"""
 
import requests
import json
import time
import argparse
import os
import urllib3
from datetime import datetime
from dotenv import load_dotenv
 
load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
 
# ── Configuration ──────────────────────────────────────────────
SPLUNK_HOST     = "https://localhost:8089"
SPLUNK_USER     = "muna"   # change this to your Splunk username
SPLUNK_PASS     = os.getenv("SPLUNK_PASSWORD", "changeme")
ABUSEIPDB_KEY   = os.getenv("ABUSEIPDB_KEY", "")
CASE_LOG        = "triage_cases.json"
POLL_INTERVAL   = 60   # seconds between polls in --watch mode
LOOKBACK        = "-24h" # how far back to search for alerts
 
# ── ANSI Colors for terminal output ────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
 
 
# ══════════════════════════════════════════════════════════════
# PART 1: SPLUNK QUERIES
# These SPL searches pull the exact alerts your detection rules fire.
# ══════════════════════════════════════════════════════════════
 
# Each entry defines:
#   name       — human-readable alert name
#   spl        — the Splunk search to find recent hits
#   technique  — MITRE ATT&CK ID
#   severity   — High / Medium / Low
#   ip_field   — which field contains the attacker IP (for enrichment)
 
ALERT_SEARCHES = [
    {
        "name": "SSH Brute Force",
        "spl": (
            'index=main sourcetype=linux_secure "Failed password" '
            '| rex field=_raw "from (?P<src_ip>\\S+) port" '
            '| stats count as attempts by src_ip '
            '| where attempts > 10'
        ),
        "technique": "T1110.001",
        "severity": "High",
        "ip_field": "src_ip"
    },
    {
        "name": "Password Spraying",
        "spl": (
            'index=main sourcetype=linux_secure "Failed password" '
            '| rex field=_raw "for (?:invalid user )?(?P<username>\\S+) from (?P<src_ip>\\S+)" '
            '| stats dc(username) as unique_users, count as attempts by src_ip '
            '| where unique_users > 3 AND attempts > 10'
        ),
        "technique": "T1110.003",
        "severity": "High",
        "ip_field": "src_ip"
    },
    {
        "name": "New User Account Created",
        "spl": (
            'index=main sourcetype=WinEventLog EventCode=4720 '
            '| table _time, src_user, user, dest'
        ),
        "technique": "T1078",
        "severity": "Medium",
        "ip_field": None   # No IP to enrich for Windows account events
    },
    {
        "name": "Scheduled Task Created",
        "spl": (
            'index=main sourcetype=WinEventLog EventCode=4698 '
            '| table _time, src_user, TaskName'
        ),
        "technique": "T1053.005",
        "severity": "Medium",
        "ip_field": None
    },
    {
        "name": "Windows Event Log Cleared",
        "spl": (
            'index=main sourcetype=WinEventLog '
            '(EventCode=1102 OR EventCode=104) '
            '| table _time, src_user, Message'
        ),
        "technique": "T1070.001",
        "severity": "High",
        "ip_field": None
    },
]
 
 
# ══════════════════════════════════════════════════════════════
# PART 2: SPLUNK API FUNCTIONS
# The Splunk REST API lets you run searches programmatically.
# This is how SOAR tools pull alert data without a human clicking.
# ══════════════════════════════════════════════════════════════
 
def splunk_search(spl: str, earliest: str = "-1h") -> list:
    """
    Run a Splunk search via the REST API and return results as a list of dicts.
 
    How it works:
      1. POST to /services/search/jobs — creates a search job, returns job ID (sid)
      2. GET /services/search/jobs/{sid} — poll until status is DONE
      3. GET /services/search/jobs/{sid}/results — fetch the actual results
    """
    auth = (SPLUNK_USER, SPLUNK_PASS)
 
    # Step 1: Create the search job
    try:
        create_resp = requests.post(
            f"{SPLUNK_HOST}/services/search/jobs",
            auth=auth,
            verify=False,
            data={
                "search": f"search {spl}",
                "earliest_time": earliest,
                "latest_time": "now",
                "output_mode": "json"
            },
            timeout=15
        )
        create_resp.raise_for_status()
        sid = create_resp.json().get("sid")
        if not sid:
            return []
    except Exception as e:
        print(f"{RED}[!] Splunk job creation failed: {e}{RESET}")
        return []
 
    # Step 2: Poll until the job is done
    for _ in range(30):  # max 30 seconds wait
        try:
            status_resp = requests.get(
                f"{SPLUNK_HOST}/services/search/jobs/{sid}",
                auth=auth,
                verify=False,
                params={"output_mode": "json"},
                timeout=10
            )
            dispatch_state = (
                status_resp.json()
                .get("entry", [{}])[0]
                .get("content", {})
                .get("dispatchState", "")
            )
            if dispatch_state == "DONE":
                break
            time.sleep(1)
        except Exception:
            time.sleep(1)
 
    # Step 3: Fetch results
    try:
        results_resp = requests.get(
            f"{SPLUNK_HOST}/services/search/jobs/{sid}/results",
            auth=auth,
            verify=False,
            params={"output_mode": "json", "count": 50},
            timeout=10
        )
        return results_resp.json().get("results", [])
    except Exception as e:
        print(f"{RED}[!] Failed to fetch results: {e}{RESET}")
        return []
 
 
# ══════════════════════════════════════════════════════════════
# PART 3: THREAT INTEL ENRICHMENT
# Before a human analyst looks at an alert, we can automatically
# look up the source IP to know if it's a known bad actor.
# AbuseIPDB is a free threat intel database — think of it as a
# reputation score for IP addresses.
# ══════════════════════════════════════════════════════════════
 
def enrich_ip(ip: str) -> dict:
    """
    Look up an IP address in AbuseIPDB.
    Returns a dict with abuse score, country, ISP, and report count.
    If no API key is configured, returns a placeholder.
    """
    if not ABUSEIPDB_KEY:
        return {
            "abuse_score": -1,
            "country": "Unknown",
            "isp": "Unknown",
            "total_reports": 0,
            "is_tor": False,
            "note": "No AbuseIPDB key configured — skipping enrichment"
        }
 
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        d = resp.json().get("data", {})
        return {
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "country": d.get("countryCode", "Unknown"),
            "isp": d.get("isp", "Unknown"),
            "total_reports": d.get("totalReports", 0),
            "is_tor": d.get("isTor", False),
            "last_reported": d.get("lastReportedAt", "Never")
        }
    except Exception as e:
        return {"abuse_score": -1, "error": str(e)}
 
 
def classify_ip_risk(enrichment: dict) -> str:
    """
    Classify an IP as HIGH / MEDIUM / LOW threat based on AbuseIPDB data.
    This is the kind of simple decision logic that SOAR uses to auto-triage.
    """
    score = enrichment.get("abuse_score", 0)
    is_tor = enrichment.get("is_tor", False)
 
    if score < 0:
        return "UNKNOWN"
    if score >= 75 or is_tor:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"
 
 
# ══════════════════════════════════════════════════════════════
# PART 4: TRIAGE LOGIC
# Given what we know about an alert + the IP enrichment,
# make an automated first-pass triage recommendation.
# A real analyst still reviews everything — this just front-loads the work.
# ══════════════════════════════════════════════════════════════
 
def make_triage_decision(alert_def: dict, result: dict, enrichment: dict) -> dict:
    """
    Combine alert data + threat intel into a triage decision.
 
    Returns a dict with:
      - disposition: TRUE_POSITIVE / LIKELY_TP / NEEDS_REVIEW / LIKELY_FP
      - recommended_action: what to do next
      - confidence: how confident we are
    """
    severity  = alert_def["severity"]
    ip_risk   = classify_ip_risk(enrichment)
    abuse_score = enrichment.get("abuse_score", -1)
 
    # Decision matrix
    # High severity alert + high-risk IP = very likely a real attack
    if severity == "High" and ip_risk == "HIGH":
        return {
            "disposition": "TRUE_POSITIVE",
            "confidence": "High",
            "recommended_action": (
                "Block source IP at firewall immediately. "
                "Review auth logs for successful logins from this IP. "
                "Escalate to Tier 2 if any successful auth found."
            )
        }
 
    if severity == "High" and ip_risk == "MEDIUM":
        return {
            "disposition": "LIKELY_TP",
            "confidence": "Medium",
            "recommended_action": (
                "Review full authentication logs for this IP. "
                "Check if any logins succeeded. Consider temporary IP block."
            )
        }
 
    if severity == "High" and ip_risk in ("LOW", "UNKNOWN") and abuse_score >= 0:
        return {
            "disposition": "NEEDS_REVIEW",
            "confidence": "Low",
            "recommended_action": (
                "IP appears clean in threat intel but alert threshold was crossed. "
                "Check if this is an internal scanner, authorized pen test, or misconfigured service."
            )
        }
 
    if severity == "Medium":
        return {
            "disposition": "NEEDS_REVIEW",
            "confidence": "Medium",
            "recommended_action": (
                "Verify the activity with the relevant system owner. "
                "Confirm if change was authorized. Document findings in case log."
            )
        }
 
    return {
        "disposition": "NEEDS_REVIEW",
        "confidence": "Low",
        "recommended_action": "Manual review required. Insufficient data for automated triage."
    }
 
 
# ══════════════════════════════════════════════════════════════
# PART 5: CASE LOGGING
# Every alert processed gets written to a structured case log.
# This is the audit trail — important for compliance and handoffs.
# ══════════════════════════════════════════════════════════════
 
def load_cases() -> list:
    if not os.path.exists(CASE_LOG):
        return []
    with open(CASE_LOG) as f:
        return json.load(f)
 
def save_case(case: dict):
    cases = load_cases()
    cases.append(case)
    with open(CASE_LOG, "w") as f:
        json.dump(cases, f, indent=2)
 
def generate_case_id() -> str:
    cases = load_cases()
    num = len(cases) + 1
    return f"CASE-{datetime.now().strftime('%Y%m%d')}-{num:03d}"
 
 
# ══════════════════════════════════════════════════════════════
# PART 6: MAIN TRIAGE LOOP
# Pulls all alerts, enriches each one, makes a decision, logs it.
# ══════════════════════════════════════════════════════════════
 
def print_case(case: dict):
    """Pretty-print a triage case to the terminal."""
    disp = case["disposition"]
    color = (
        RED    if disp == "TRUE_POSITIVE"  else
        YELLOW if disp == "LIKELY_TP"      else
        CYAN   if disp == "NEEDS_REVIEW"   else
        GREEN
    )
    print(f"\n{'─'*58}")
    print(f"{BOLD}  {case['case_id']}  |  {case['alert_name']}{RESET}")
    print(f"  Technique : {case['technique']}")
    print(f"  Severity  : {case['alert_severity']}")
    if case.get("source_ip"):
        print(f"  Source IP : {case['source_ip']}")
        intel = case.get("threat_intel", {})
        print(f"  Abuse Score: {intel.get('abuse_score', 'N/A')}%  |  "
              f"Country: {intel.get('country', '?')}  |  "
              f"ISP: {intel.get('isp', '?')}")
        print(f"  IP Risk   : {case['ip_risk']}")
    print(f"  {color}{BOLD}Decision  : {disp}{RESET}  (Confidence: {case['confidence']})")
    print(f"  Action    : {case['recommended_action']}")
    print(f"  Logged    : {case['timestamp']}")
 
def run_triage(verbose: bool = True):
    """Run one full triage cycle across all alert searches."""
    print(f"\n{BOLD}{'═'*58}")
    print(f"  AUTO TRIAGE — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═'*58}{RESET}")
 
    new_cases = 0
    already_seen = {c.get("alert_key") for c in load_cases()}
 
    for alert_def in ALERT_SEARCHES:
        if verbose:
            print(f"\n{GRAY}[→] Querying: {alert_def['name']}...{RESET}")
 
        results = splunk_search(alert_def["spl"], earliest=LOOKBACK)
 
        if not results:
            if verbose:
                print(f"{GRAY}    No results found.{RESET}")
            continue
 
        print(f"    {len(results)} hit(s) found for {alert_def['name']}")
 
        for result in results:
            # Build a dedup key so we don't create duplicate cases
            ip = result.get(alert_def.get("ip_field") or "", "") or result.get("src_ip", "")
            alert_key = f"{alert_def['name']}|{ip}|{datetime.now().strftime('%Y%m%d%H')}"
 
            if alert_key in already_seen:
                print(f"{GRAY}    [skip] Already triaged this hour.{RESET}")
                continue
            already_seen.add(alert_key)
 
            # Enrich the source IP if we have one
            enrichment = {}
            ip_risk = "N/A"
            if ip:
                enrichment = enrich_ip(ip)
                ip_risk = classify_ip_risk(enrichment)
 
            # Make triage decision
            decision = make_triage_decision(alert_def, result, enrichment)
 
            # Build the case record
            case = {
                "case_id": generate_case_id(),
                "alert_key": alert_key,
                "timestamp": datetime.now().isoformat(),
                "alert_name": alert_def["name"],
                "technique": alert_def["technique"],
                "alert_severity": alert_def["severity"],
                "source_ip": ip or None,
                "raw_result": result,
                "threat_intel": enrichment,
                "ip_risk": ip_risk,
                "disposition": decision["disposition"],
                "confidence": decision["confidence"],
                "recommended_action": decision["recommended_action"],
                "status": "Auto-triaged — Pending analyst review"
            }
 
            save_case(case)
            new_cases += 1
 
            if verbose:
                print_case(case)
 
    print(f"\n{BOLD}{'─'*58}")
    print(f"  Triage complete. {new_cases} new case(s) created.")
    print(f"  All cases logged to: {CASE_LOG}")
    print(f"{'─'*58}{RESET}\n")
 
def print_case_summary():
    """Print a summary of all cases in the log."""
    cases = load_cases()
    if not cases:
        print("No cases logged yet.")
        return
 
    from collections import Counter
    disp_counts = Counter(c["disposition"] for c in cases)
 
    print(f"\n{'═'*45}")
    print(f"  CASE LOG SUMMARY  ({len(cases)} total cases)")
    print(f"{'═'*45}")
    for disp, count in disp_counts.most_common():
        print(f"  {disp:<22} : {count}")
    print(f"{'─'*45}")
    print(f"  Log file: {CASE_LOG}")
    print(f"{'═'*45}\n")
 
 
# ══════════════════════════════════════════════════════════════
# ENTRYPOINT
# ══════════════════════════════════════════════════════════════
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Automated alert triage for Splunk SIEM Homelab"
    )
    parser.add_argument(
        "--watch", action="store_true",
        help=f"Poll continuously every {POLL_INTERVAL} seconds"
    )
    parser.add_argument(
        "--summary", action="store_true",
        help="Print case log summary and exit"
    )
    args = parser.parse_args()
 
    if args.summary:
        print_case_summary()
 
    elif args.watch:
        print(f"{BOLD}[WATCH MODE] Polling every {POLL_INTERVAL}s — Ctrl+C to stop{RESET}")
        try:
            while True:
                run_triage()
                time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            print("\n[!] Stopped by user.\n")
 
    else:
        run_triage()
