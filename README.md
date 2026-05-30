# 🛡️ Splunk SIEM Homelab — Live Threat Detection

 
**SIEM:** Splunk Enterprise (Oracle Linux VM)  
**Attack Platform:** Kali Linux VM  
**Status:** Complete 

---

## 📌 Overview

a fully functional SOC environment built from scratch to simulate real-world threat detection, alert engineering, and incident response. this lab mirrors enterprise SOC operations through ingesting live logs, detecting attacks in real time, and documenting findings through a professional incident report.

---

## 🏗️ Architecture

<img width="608" height="420" alt="architecture-diagram" src="https://github.com/user-attachments/assets/80e7a8d8-bbed-49e4-8eb0-0f0c61fab7d9" />




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

## Detection Rules Built

### Rule 1 — SSH Brute Force

```spl
index=main sourcetype=linux_secure "Failed password"
| stats count by host
| where count > 5
```

- **Trigger:** failed SSH attempts exceed 5 — runs every 5 min
- **MITRE:** T1110.001 — Brute Force: Password Guessing

---

### Rule 2 — Failed Windows Logins

```spl
index=main sourcetype=WinEventLog EventCode=4625
| stats count by Account_Name, host
| where count > 3
```

- **Trigger:** failed logons exceed 3 — runs every 5 min
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

full incident report documenting the SSH brute force attack that covers: attack timeline, SPL queries, MITRE ATT&CK mapping, evidence, response actions, and remediation recommendations.

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

## SOC Overview dashboard 
<img width="1286" height="601" alt="splunk-dashboard_2" src="https://github.com/user-attachments/assets/dd462242-00d9-4e52-9bbb-c1a135ae4a6c" />
<img width="1264" height="630" alt="splunk-dashboard_1" src="https://github.com/user-attachments/assets/9c295826-c89d-445e-b26f-ae0df6926233" />

## Windows Event ID 4625 failed login detection 

<img width="1281" height="681" alt="wineventlog-results" src="https://github.com/user-attachments/assets/0b7b4493-bb40-46d8-b2bd-83c051422b42" />

## Nmap reconnaissance from Kali 

<img width="1674" height="549" alt="nmap-scan" src="https://github.com/user-attachments/assets/eb214601-9e9b-427a-a4e6-d9a7284ec7d6" />

## Hydra SSH brute force running

<img width="1723" height="919" alt="hydra-brute-force" src="https://github.com/user-attachments/assets/d2fc47bd-87d0-4265-ac16-bc75bf3501c1" />


## Linux auth logs with kali ip detected 

<img width="1318" height="648" alt="inux-secure-logs" src="https://github.com/user-attachments/assets/47fab699-18de-48b8-a720-bd0970a3121c" />

## Detection alerts configured 

<img width="1359" height="625" alt="alerts-saved" src="https://github.com/user-attachments/assets/73b4f2aa-55f6-41bc-9eb8-3bb6eb76ee5b" />

---

## 🐍 Scripts
 
 python script built for CCDC 2026 — auto-deploys 59 scheduled Splunk alerts via REST API 

---

## What I'd Do Next in a Real SOC

1. set up fail2ban & auto-block after 5 failed SSH attempts
2. disable password SSH and use key-based auth only
3. addd threat intel feeds (AbuseIPDB, VirusTotal enrichment)
4. tune thresholds so baseline normal behavior to cut false positives
5. build SOAR playbooks; automated containment on brute force alerts
6. expand log sources (DNS, proxy, firewall for full kill chain visibility)

---

## 🧰 Skills Demonstrated

`Splunk` `Log Ingestion` `Windows Event Logs` `Linux Auth Logs` `Detection Engineering` `Alert Triage` `Dashboard Building` `Incident Response` `Incident Reporting` `MITRE ATT&CK` `Kali Linux` `Hydra` `Nmap` `Python` `Blue Team`

---
