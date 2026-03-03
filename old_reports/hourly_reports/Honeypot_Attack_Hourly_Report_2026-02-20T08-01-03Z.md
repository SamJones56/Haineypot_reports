# Honeypot Attack Report - 2026-02-20T08:00:15Z

## Executive Summary:
- **High Volume of Attacks:** A total of 6,234 attacks were observed in the last hour, with a significant portion originating from Indonesia.
- **Dominant Attacker:** The IP address 182.10.97.25 from Indonesia, associated with AS23693 (PT. Telekomunikasi Selular), was responsible for 2,664 attacks, making it the most aggressive source.
- **Common Tactics:** The most frequent alert category was "Generic Protocol Command Decode" with 4,645 instances. The top alert signature was "GPL INFO VNC server response" with 2,296 hits.
- **Exploitation Attempts:** While there were a few attempts to exploit various CVEs, the numbers are low, suggesting opportunistic scanning rather than a targeted campaign.
- **Credential Stuffing:** The most common usernames attempted were "admin" and "root", with common passwords like "password" and "admin" being used.
- **Operating System Distribution:** The attackers' operating systems are predominantly identified as Windows NT kernel and Linux 2.2.x-3.x.

## Detailed Analysis:

**Total Attacks:**
- 6234

**Top Attacking Countries:**
- Indonesia: 2672
- United States: 1034
- Germany: 485
- Singapore: 391
- Netherlands: 194

**Notable IP Reputations:**
- known attacker: 1224
- mass scanner: 276
- bot, crawler: 2

**Common Alert Categories:**
- Generic Protocol Command Decode: 4645
- Misc activity: 2405
- Misc Attack: 424
- Attempted Information Leak: 77
- Potentially Bad Traffic: 33
- Attempted Administrator Privilege Gain: 17
- Web Application Attack: 4
- Detection of a Denial of Service Attack: 3
- Detection of a Network Scan: 3
- Potential Corporate Privacy Violation: 3

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 2296
- 2200003 - SURICATA IPv4 truncated packet: 2216
- 2200122 - SURICATA AF-PACKET truncated packet: 2216
- 2402000 - ET DROP Dshield Block Listed Source group 1: 120
- 2001978 - ET INFO SSH session in progress on Expected Port: 47
- 2009582 - ET SCAN NMAP -sS window 1024: 41
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 35
- 2210048 - SURICATA STREAM reassembly sequence GAP -- missing packet(s): 31
- 2221036 - SURICATA HTTP Response excessive header repetition: 29
- 2210051 - SURICATA STREAM Packet with broken ack: 28

**ASN Information:**
- 23693, PT. Telekomunikasi Selular: 2664
- 14061, DigitalOcean, LLC: 1089
- 8075, Microsoft Corporation: 410
- 396982, Google LLC: 295
- 174, Cogent Communications, LLC: 154
- 49724, JSC Vainah Telecom: 139
- 213412, ONYPHE SAS: 125
- 16509, Amazon.com, Inc.: 78
- 398324, Censys, Inc.: 78
- 51852, Private Layer INC: 62

**Source IP Addresses:**
- 182.10.97.25: 2664
- 4.145.113.4: 387
- 164.90.185.60: 246
- 170.64.175.89: 175
- 46.101.240.14: 168
- 159.89.167.231: 145
- 188.0.175.155: 139
- 34.158.168.101: 99
- 143.110.137.200: 71
- 46.19.137.194: 62

**Country to Port Mapping:**
- Germany
  - 22: 82
  - 2335: 4
  - 10429: 4
  - 22133: 4
  - 23972: 4
- Indonesia
  - 445: 2664
  - 9481: 7
  - 1433: 1
- Netherlands
  - 443: 97
  - 22: 9
  - 6036: 8
  - 3306: 6
  - 80: 5
- Singapore
  - 5901: 39
  - 5904: 39
  - 5906: 39
  - 5907: 39
  - 5908: 39
- United States
  - 8728: 20
  - 25: 15
  - 9100: 14
  - 80: 12
  - 9300: 12

**CVEs Exploited:**
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2024-14007 CVE-2024-14007: 2
- CVE-2025-55182 CVE-2025-55182: 2
- CVE-2023-26801 CVE-2023-26801: 1

**Usernames:**
- admin: 69
- root: 51
- test: 9
- backup: 8
- daemon: 8
- ubuntu: 8
- user: 6
- hadoop: 3
- orangepi: 3
- anonymous: 2

**Passwords:**
- : 10
- password: 9
- admin: 8
- 1234: 7
- 123: 6
- admin123: 6
- password1: 6
- 123456: 5
- 1q2w3e4r: 5
- 654321: 5

**OS Distribution:**
- Windows NT kernel: 17024
- Linux 2.2.x-3.x: 14109
- Windows NT kernel 5.x: 9911
- Windows 7 or 8: 2818
- Linux 2.2.x-3.x (barebone): 486
- Linux 2.2.x-3.x (no timestamps): 169
- Linux 3.11 and newer: 51
- Mac OS X: 37
- Linux 3.1-3.10: 30
- FreeBSD: 3

**Hyper-aggressive IPs:**
- 182.10.97.25: 2664
- 4.145.113.4: 387
- 164.90.185.60: 246
- 170.64.175.89: 175
- 46.101.240.14: 168
- 159.89.167.231: 145
- 188.0.175.155: 139
