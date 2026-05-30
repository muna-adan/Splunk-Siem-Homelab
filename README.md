# 🛡️ Splunk SIEM Homelab — Live Threat Detection

 
**SIEM:** Splunk Enterprise (Oracle Linux VM)  
**Attack Platform:** Kali Linux VM  
**Status:** Complete 

---

## 📌 Overview

A fully functional SOC environment built from scratch to simulate real-world threat detection, alert engineering, and incident response. This lab mirrors enterprise SOC operations — ingesting live logs, detecting attacks in real time, and documenting findings through a professional incident report.

---

## 🏗️ Architecture



```
Windows 11 Host (VirtualBox)
│
├── Windows Host ──[logs :9997]──► Oracle Linux VM
│   └── Splunk Universal Forwarder      └── Splunk Enterprise (SIEM)
│       └── WinEventLog: Security            └── Dashboard :8000
│           WinEventLog: System              └── /var/log/secure monitored
│           WinEventLog: Application
│
└── Kali Linux VM ──[SSH brute force + Nmap]──► Oracle Linux VM
```

---

## ⚙️ Environment

| Component | Details |
|-----------|---------|
| Host OS | Windows 11 |
| Virtualization | Oracle VirtualBox |
| SIEM | Splunk Enterprise — Oracle Linux VM |
| Log Forwarder | Splunk Universal Forwarder — Windows Host |
| Attack Platform | Kali Linux VM |
| Log Sources | Windows Event Logs (Security, System, Application), Linux `/var/log/secure` |
| Network Mode | Bridged Adapter |

---

## ⚔️ Attacks Simulated

| Attack | Tool | Target | Result |
|--------|------|--------|--------|
| Network recon | Nmap `-sV` | Oracle Linux VM | Open ports + services identified |
| SSH brute force | Hydra + rockyou.txt | Oracle Linux VM | 328 failed auth attempts |
| Failed Windows logins | Manual | Windows Host | Event ID 4625 triggered |

---

## 🔍 Detection Rules Built

### Rule 1 — SSH Brute Force

```spl
index=main sourcetype=linux_secure "Failed password"
| stats count by host
| where count > 5
```

- **Trigger:** Failed SSH attempts exceed 5 — runs every 5 min
- **MITRE:** T1110.001 — Brute Force: Password Guessing

---

### Rule 2 — Failed Windows Logins

```spl
index=main sourcetype=WinEventLog EventCode=4625
| stats count by Account_Name, host
| where count > 3
```

- **Trigger:** Failed logons exceed 3 — runs every 5 min
- **MITRE:** T1110.001 — Brute Force: Password Guessing

---

### Rule 3 — New User Account Created

```spl
index=main sourcetype=WinEventLog EventCode=4720
```

- **Trigger:** Any new Windows account creation
- **MITRE:** T1136 — Create Account

---

## 📊 SOC Dashboard — SOC Overview

| Panel | Purpose |
|-------|---------|
| Failed Windows Logins | Tracks failed auth attempts by account and host |
| SSH Brute Force Attempts | Detects SSH brute force from any source |
| Log Volume Over Time | Monitors log ingestion across all sources |

---

## 📄 Incident Report

Full incident report documenting the SSH brute force attack:

👉 [incident-report-IR-2026-001.md](./incident-report-IR-2026-001.md)

Covers: attack timeline, SPL queries, MITRE ATT&CK mapping, evidence, response actions, and remediation recommendations.

---

## 🎯 MITRE ATT&CK Coverage

| Technique | ID | Tactic |
|-----------|-----|--------|
| Brute Force: Password Guessing | T1110.001 | Credential Access |
| Remote Services: SSH | T1021.004 | Lateral Movement |
| Create Account | T1136 | Persistence |
| Network Service Discovery | T1046 | Discovery |

---

## 📸 Screenshots

| # | Screenshot | Description |
|---|-----------|-------------|
| 1 | ![Dashboard](./screenshots/01-splunk-dashboard.png) | SOC Overview dashboard |
| 2 | ![WinEventLog](./screenshots/02-wineventlog-results.png) | Windows Event Logs in Splunk |
| 3 | ![Failed Logins](./screenshots/03-failed-logins-4625.png) | Event ID 4625 detection |
| 4 | ![Nmap](./screenshots/04-nmap-scan.png) | Nmap recon from Kali |
| 5 | ![Hydra](./screenshots/05-hydra-brute-force.png) | Hydra brute force running |
| 6 | ![Linux Logs](./screenshots/06-linux-secure-logs.png) | Linux auth logs with Kali IP |
| 7 | ![Alerts](./screenshots/07-alerts-saved.png) | All 3 alerts configured |

---

## 🐍 Scripts

| File | Description |
|------|-------------|
| [`scripts/deploy_alerts.py`](./scripts/deploy_alerts.py) | Python script built for CCDC 2026 — auto-deploys 59 scheduled Splunk alerts via REST API |

---

## 💡 What I'd Do Next in a Real SOC

1. Set up fail2ban — auto-block after 5 failed SSH attempts
2. Disable password SSH — key-based auth only
3. Add threat intel feeds — AbuseIPDB, VirusTotal enrichment
4. Tune thresholds — baseline normal behavior to cut false positives
5. Build SOAR playbooks — automated containment on brute force alerts
6. Expand log sources — DNS, proxy, firewall for full kill chain visibility

---

## 🧰 Skills Demonstrated

`Splunk` `Log Ingestion` `Windows Event Logs` `Linux Auth Logs` `Detection Engineering` `Alert Triage` `Dashboard Building` `Incident Response` `Incident Reporting` `MITRE ATT&CK` `Kali Linux` `Hydra` `Nmap` `Python` `Blue Team`

---

## 📁 Repo Structure

```
splunk-siem-homelab/
├── README.md
├── incident-report-IR-2026-001.md
├── architecture-diagram.png
├── detection-rules/
│   └── alerts.conf
├── scripts/
│   └── deploy_alerts.py
└── screenshots/
    ├── 01-splunk-dashboard.png
    ├── 02-wineventlog-results.png
    ├── 03-failed-logins-4625.png
    ├── 04-nmap-scan.png
    ├── 05-hydra-brute-force.png
    ├── 06-linux-secure-logs.png
    └── 07-alerts-saved.png
```

---
