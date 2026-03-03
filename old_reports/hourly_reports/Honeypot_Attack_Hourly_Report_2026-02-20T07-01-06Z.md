# Honeypot Attack Report - 2026-02-20T07:00:18Z

### Executive Summary:
- The honeypot network observed a total of 3,390 attacks in the past hour.
- The majority of attacks originated from the United States, followed by Germany and Indonesia.
- Dominant attackers were associated with DigitalOcean, LLC and PT. Telekomunikasi Selular ASNs.
- A significant portion of source IPs were identified as known attackers and mass scanners.
- The most frequent alert signature was "GPL INFO VNC server response," indicating VNC reconnaissance activity.
- Several CVEs were detected, with CVE-2024-14007 being the most common.

### Detailed Analysis:

**Total Attacks:**
- 3390

**Top Attacking Countries:**
- United States: 928
- Germany: 575
- Indonesia: 533
- Singapore: 387
- India: 255

**Notable IP Reputations:**
- known attacker: 1292
- mass scanner: 266

**Common Alert Categories:**
- Generic Protocol Command Decode: 2532
- Misc activity: 2388
- Attempted Administrator Privilege Gain: 1414
- Misc Attack: 409
- Attempted Information Leak: 113
- Potentially Bad Traffic: 10
- Detection of a Network Scan: 8
- Not Suspicious Traffic: 3
- A Network Trojan was detected: 2
- Malware Command and Control Activity Detected: 1

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 2298
- 2024766 - ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1384
- 2200003 - SURICATA IPv4 truncated packet: 1206
- 2200122 - SURICATA AF-PACKET truncated packet: 1206
- 2402000 - ET DROP Dshield Block Listed Source group 1: 120
- 2023753 - ET SCAN MS Terminal Server Traffic on Non-standard Port: 60
- 2001978 - ET INFO SSH session in progress on Expected Port: 51
- 2009582 - ET SCAN NMAP -sS window 1024: 41
- 2210048 - SURICATA STREAM reassembly sequence GAP -- missing packet(s): 33
- 2034857 - ET HUNTING RDP Authentication Bypass Attempt: 25

**ASN Information:**
- 14061 - DigitalOcean, LLC: 1149
- 23693 - PT. Telekomunikasi Selular: 483
- 8075 - Microsoft Corporation: 413
- 174 - Cogent Communications, LLC: 189
- 396982 - Google LLC: 183
- 209334 - Modat B.V.: 143
- 213412 - ONYPHE SAS: 136
- 398324 - Censys, Inc.: 60
- 6939 - Hurricane Electric LLC: 50
- 141140 - PT Jinde Grup Indonesia: 50

**Source IP Addresses:**
- 138.68.109.50: 515
- 182.10.97.25: 483
- 4.145.113.4: 383
- 159.89.167.231: 250
- 170.64.177.47: 103
- 103.93.93.211: 50
- 85.217.149.29: 38
- 92.118.39.76: 36
- 46.225.120.91: 30
- 85.217.149.13: 30

**Country to Port Mapping:**
- Germany:
  - 22: 109
  - 9000: 11
  - 8033: 4
  - 21794: 4
  - 8315: 3
- India:
  - 22: 49
  - 445: 5
- Indonesia:
  - 445: 483
  - 23: 25
  - 2222: 1
- Singapore:
  - 5902: 39
  - 5903: 39
  - 5905: 39
  - 5901: 38
  - 5904: 38
- United States:
  - 5601: 14
  - 22: 10
  - 9100: 10
  - 25: 9
  - 4443: 9

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2002-0606: 2
- CVE-2020-2551 CVE-2020-2551 CVE-2020-2551: 2
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- root: 80
- ansible: 10
- apache: 10
- docker: 10
- dspace: 10
- jenkins: 10
- nagios: 10
- nginx: 10
- tomcat: 10
- zabbix: 10

**Passwords:**
- 12345: 13
- 123456: 12
- 123456789: 12
- admin: 12
- password: 12
- root: 12
- welcome: 11
- : 4
- 1234: 4
- 112233: 2

**OS Distribution:**
- Linux 2.2.x-3.x: 11767
- Windows NT kernel: 16880
- Windows NT kernel 5.x: 9149
- Linux 2.2.x-3.x (barebone): 486
- Linux 2.2.x-3.x (no timestamps): 57
- Linux 3.11 and newer: 51
- Mac OS X: 44
- Linux 3.1-3.10: 28
- Windows 7 or 8: 500
- FreeBSD: 2

**Hyper-aggressive IPs:**
- 138.68.109.50: 515
- 182.10.97.25: 483
- 4.145.113.4: 383
- 159.89.167.231: 250
- 170.64.177.47: 103
