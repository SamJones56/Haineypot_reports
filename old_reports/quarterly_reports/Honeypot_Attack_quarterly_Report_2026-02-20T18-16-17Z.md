# Honeypot Attack Report - 2026-02-20T18:15:26Z

## Executive Summary:
- **High Attack Volume:** Over 34,000 attacks were observed in the last 6 hours, indicating a significant level of malicious activity.
- **Dominant Attacker:** A single IP address, 88.86.119.38, originating from Czechia and associated with ASN 39392 (SH.cz s.r.o.), was responsible for nearly 15% of all attacks.
- **Geographic Concentration:** Attacks are globally distributed, with the top five countries (India, United States, Czechia, Russia, and Azerbaijan) accounting for a substantial portion of the total attack volume.
- **Common Vulnerabilities:** The most frequently observed alert signature was "GPL INFO VNC server response", suggesting widespread scanning for exposed VNC servers. Additionally, the "DoublePulsar Backdoor" signature indicates attempts to exploit systems compromised by this NSA-developed malware.
- **Credential Brute-Forcing:** The most commonly attempted usernames and passwords are "root", "admin", "123456", and "password", highlighting the continued prevalence of brute-force attacks using default or weak credentials.
- **Operating System Targeting:** The most frequently fingerprinted operating systems were variants of Linux and Windows, suggesting that attackers are targeting a broad range of systems.

## Detailed Analysis:

**Total Attacks:**
- 34,108

**Top Attacking Countries:**
- India: 5230
- United States: 5173
- Czechia: 5041
- Russia: 3155
- Azerbaijan: 1827

**Notable IP Reputations:**
- known attacker: 7941
- mass scanner: 1127
- bot, crawler: 5

**Common Alert Categories:**
- Generic Protocol Command Decode: 10059
- Misc activity: 10010
- Misc Attack: 2226
- Attempted Administrator Privilege Gain: 1288
- Attempted Information Leak: 1211

**Alert Signatures:**
- 2100560: GPL INFO VNC server response: 9164
- 2200003: SURICATA IPv4 truncated packet: 4445
- 2200122: SURICATA AF-PACKET truncated packet: 4445
- 2024766: ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1210
- 2002824: ET INFO CURL User Agent: 798

**ASN Information:**
- 14061: DigitalOcean, LLC: 5375
- 39392: SH.cz s.r.o.: 4995
- 12389: Rostelecom: 3111
- 24560: Bharti Airtel Ltd., Telemedia Services: 2124
- 39232: Uninet LLC: 1827

**Source IP Addresses:**
- 88.86.119.38: 4995
- 83.219.7.170: 3111
- 122.180.29.138: 2124
- 185.18.245.87: 1827
- 200.105.151.2: 1806

**Country to Port Mapping:**
- **Azerbaijan**
  - 445: 1827
- **Czechia**
  - 2323: 3471
  - 23: 762
  - 80: 46
- **India**
  - 445: 3499
  - 22: 342
  - 50501: 8
  - 23: 3
  - 5901: 2
- **Russia**
  - 445: 3111
  - 3372: 8
  - 27961: 7
  - 5601: 6
  - 8888: 4
- **United States**
  - 445: 831
  - 22: 164
  - 8728: 62
  - 80: 55
  - 11211: 45

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 19
- CVE-2025-55182 CVE-2025-55182: 10
- CVE-2021-3449 CVE-2021-3449: 9
- CVE-2019-11500 CVE-2019-11500: 6
- CVE-2023-46604 CVE-2023-46604 CVE-2023-46604: 6

**Usernames:**
- root: 417
- sa: 147
- admin: 113
- sol: 42
- user: 40

**Passwords:**
- 123456: 104
- password: 61
- 1234: 54
- admin: 45
- 123: 38

**OS Distribution:**
- Linux 2.2.x-3.x: 96353
- Windows NT kernel: 103812
- Linux 2.2.x-3.x (barebone): 1899
- Windows NT kernel 5.x: 55364
- Linux 2.2.x-3.x (no timestamps): 1028

**Hyper-aggressive IPs:**
- 88.86.119.38: 4995
- 83.219.7.170: 3111
- 122.180.29.138: 2124
- 185.18.245.87: 1827
- 200.105.151.2: 1806
