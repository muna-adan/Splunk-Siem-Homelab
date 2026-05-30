🛡️ Splunk SIEM Homelab — Live Threat Detection

Environment: Oracle VirtualBox — Windows 11 Host
SIEM: Splunk Enterprise (Oracle Linux VM)
Attack Platform: Kali Linux VM
Status: Complete 

📌 Overview
A fully functional Security Operations Center (SOC) environment built from scratch to simulate real-world threat detection, alert engineering, and incident response workflows. This lab mirrors enterprise SOC operations — ingesting live logs, detecting attacks in real time, and documenting findings through professional incident reports.

🏗️ Architecture
┌─────────────────────────────────────────────────────────────┐
│               Windows 11 Host — Oracle VirtualBox            │
│                                                               │
│  ┌──────────────────────┐        ┌────────────────────────┐  │
│  │   Windows 11 Host    │──logs─▶│   Oracle Linux VM      │  │
│  │                      │ :9997  │                        │  │
│  │  Splunk Universal    │        │  Splunk Enterprise     │  │
│  │  Forwarder           │        │  SIEM / Log Indexer    │  │
│  │                      │        │  Dashboard → :8000     │  │
│  │  WinEventLog:        │        │  /var/log/secure       │  │
│  │  Security            │        │  monitored             │  │
│  │  System              │        └────────────┬───────────┘  │
│  │  Application         │                     │ alerts       │
│  └──────────────────────┘                     ▼              │
│                                    ┌────────────────────┐    │
│  ┌──────────────────────┐          │   SOC Dashboard    │    │
│  │   Kali Linux VM      │          │                    │    │
│  │                      │──attack─▶│   3 Detection      │    │
│  │  Hydra (brute force) │          │   Rules            │    │
│  │  Nmap (recon)        │          │   Alerts           │    │
│  └──────────────────────┘          │   Dashboards       │    │
│                                    └────────────────────┘    │
└─────────────────────────────────────────────────────────────┘

⚙️ Environment
ComponentDetailsHost OSWindows 11VirtualizationOracle VirtualBoxSIEMSplunk Enterprise — Oracle Linux VMLog ForwarderSplunk Universal Forwarder — Windows HostAttack PlatformKali Linux VMLog SourcesWindows Event Logs (Security, System, Application), Linux /var/log/secureNetwork ModeBridged Adapter

⚔️ Attacks Simulated
AttackToolTargetEvents GeneratedNetwork reconnaissanceNmap -sVOracle Linux VMOpen ports, running servicesSSH brute forceHydra + rockyou.txtOracle Linux VM328 failed auth attemptsFailed Windows loginsManualWindows HostEvent ID 4625 — 4 events

🔍 Detection Rules Built
Rule 1 — SSH Brute Force Detection
splindex=main sourcetype=linux_secure "Failed password"
| stats count by host
| where count > 5
Alert: Triggers when SSH failed attempts exceed 5 — scheduled every 5 minutes
MITRE ATT&CK: T1110.001 — Brute Force: Password Guessing

Rule 2 — Failed Windows Login Detection
splindex=main sourcetype=WinEventLog EventCode=4625
| stats count by Account_Name, host
| where count > 3
Alert: Triggers when failed logon count exceeds 3 — scheduled every 5 minutes
MITRE ATT&CK: T1110.001 — Brute Force: Password Guessing

Rule 3 — New User Account Creation
splindex=main sourcetype=WinEventLog EventCode=4720
Alert: Triggers on any new Windows account creation event
MITRE ATT&CK: T1136 — Create Account

📊 SOC Dashboard
Three-panel Splunk dashboard — SOC Overview:
PanelSearchPurposeFailed Windows LoginsEventCode=4625 stats by Account_NameTrack credential attacks on WindowsSSH Brute Force Attemptslinux_secure "Failed password" stats by hostDetect SSH brute force from any sourceLog Volume Over Timetimechart count by sourcetypeMonitor log ingestion health across all sources

📄 Incident Report
A full professional incident report documenting the SSH brute force attack is included:
📋 incident-report-IR-2026-001.md
Covers:

Full attack timeline
Detection methodology and SPL queries used
MITRE ATT&CK mapping (T1110.001, T1021.004)
Evidence documentation
Response actions taken
Prioritized remediation recommendations


🎯 MITRE ATT&CK Coverage
TechniqueIDTacticDetectionBrute Force: Password GuessingT1110.001Credential Accesslinux_secure Failed password ruleRemote Services: SSHT1021.004Lateral MovementSSH brute force alertCreate AccountT1136PersistenceEventCode 4720 alertNetwork Service DiscoveryT1046DiscoveryNmap scan logs

📸 Screenshots
FileDescriptionscreenshots/01-splunk-dashboard.pngSOC Overview dashboard — all 3 panelsscreenshots/02-wineventlog-results.pngWindows Event Logs flowing into Splunkscreenshots/03-failed-logins-4625.pngEvent ID 4625 failed login detectionscreenshots/04-nmap-scan.pngNmap reconnaissance from Kaliscreenshots/05-hydra-brute-force.pngHydra SSH brute force runningscreenshots/06-linux-secure-logs.pngLinux auth logs with Kali IP detectedscreenshots/07-alerts-saved.pngAll 3 detection alerts configured

💡 What I Would Do Next in a Real SOC

Implement fail2ban — auto-block IPs after 5 failed SSH attempts
Disable password-based SSH — enforce key-based authentication only
Add threat intelligence feeds — enrich alerts with AbuseIPDB or VirusTotal
Tune alert thresholds — baseline normal behavior to reduce false positives
Build automated response playbooks — SOAR integration for containment
Expand log sources — DNS, proxy, firewall logs for full kill chain visibility


🧰 Skills Demonstrated
Splunk Enterprise Log Ingestion Windows Event Log Analysis Linux Auth Log Analysis Threat Detection Alert Engineering Detection Rules Dashboard Building Incident Response Incident Reporting MITRE ATT&CK Kali Linux Hydra Nmap Python Blue Team Operations

📁 Repository Structure
splunk-siem-homelab/
├── README.md (you're here)
├── incident-report-IR-2026-001.md
├── architecture-diagram.png
├── detection-rules/
│   └── alerts.conf
└── screenshots/
    ├── 01-splunk-dashboard.png
    ├── 02-wineventlog-results.png
    ├── 03-failed-logins-4625.png
    ├── 04-nmap-scan.png
    ├── 05-hydra-brute-force.png
    ├── 06-linux-secure-logs.png
    └── 07-alerts-saved.png
