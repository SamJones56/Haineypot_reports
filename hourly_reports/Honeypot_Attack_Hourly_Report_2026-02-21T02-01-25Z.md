
# Honeypot Attack Report - 2026-02-21T02:00:19Z

## Executive Summary:
- Over 6,200 attacks were recorded in the past hour, with a significant concentration from India, the United States, and Canada.
- Four IP addresses were identified as hyper-aggressive, each responsible for over 400 attacks, with the most active IP (167.71.234.239) launching over 2,100 attacks.
- The dominant attacker ASN is DigitalOcean, LLC (14061), accounting for over 3,200 attacks.
- The most common alert category was "Generic Protocol Command Decode", and high-volume signatures included "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet".
- Brute-force activity remains prevalent, with "root" being the most targeted username and "123456" the most common password.
- The primary attacking operating system appears to be Linux-based.

## Detailed Analysis:

**Total Attacks:**
- 6284

**Top Attacking Countries:**
- India: 2194
- United States: 1193
- Canada: 1156
- Germany: 500
- Switzerland: 476

**Notable IP Reputations:**
- known attacker: 2468
- mass scanner: 223

**Common Alert Categories:**
- Generic Protocol Command Decode: 1652
- Misc activity: 457
- Misc Attack: 447
- Attempted Information Leak: 97
- Potentially Bad Traffic: 81

**Alert Signatures:**
- ID: 2200003, Signature: SURICATA IPv4 truncated packet, Count: 621
- ID: 2200122, Signature: SURICATA AF-PACKET truncated packet, Count: 621
- ID: 2100560, Signature: GPL INFO VNC server response, Count: 228
- ID: 2228000, Signature: SURICATA SSH invalid banner, Count: 221
- ID: 2402000, Signature: ET DROP Dshield Block Listed Source group 1, Count: 167

**ASN Information:**
- ASN: 14061, Organization: DigitalOcean, LLC, Count: 3207
- ASN: 51852, Organization: Private Layer INC, Count: 476
- ASN: 210006, Organization: Shereverov Marat Ahmedovich, Count: 450
- ASN: 396982, Organization: Google LLC, Count: 320
- ASN: 47890, Organization: Unmanaged Ltd, Count: 307

**Source IP Addresses:**
- 167.71.234.239: 2125
- 146.190.242.202: 996
- 46.19.137.194: 476
- 178.20.210.32: 450
- 86.54.24.29: 118

**Country to Port Mapping:**
- **Canada:**
  - 22: 197
  - 8728: 4
  - 2945: 2
  - 6725: 2
  - 7359: 2
- **Germany:**
  - 22: 90
  - 20000: 10
  - 50000: 10
  - 6140: 4
  - 43208: 4
- **India:**
  - 22: 423
  - 80: 54
  - 443: 13
  - 23: 1
- **Switzerland:**
  - 5434: 443
  - 5444: 30
  - 5432: 3
- **United States:**
  - 445: 69
  - 9093: 57
  - 8999: 23
  - 9100: 20
  - 9443: 13

**CVEs Exploited:**
- CVE-2025-55182 CVE-2025-55182: 6
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2023-46604 CVE-2023-46604 CVE-2023-46604: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2

**Usernames:**
- root: 172
- admin: 23
- user: 21
- ubuntu: 20
- test: 16
- deploy: 15
- student: 13
- steam: 11
- postgres: 10
- www: 10

**Passwords:**
- 123456: 73
- password: 27
- P@ssw0rd: 18
- 123: 16
- p@ssw0rd: 13

**OS Distribution:**
- Linux 2.2.x-3.x: 6014
- Windows NT kernel: 3590
- Linux 2.2.x-3.x (barebone): 485
- Windows NT kernel 5.x: 144
- Linux 2.2.x-3.x (no timestamps): 145

**Hyper-aggressive IPs:**
- 167.71.234.239: 2125
- 146.190.242.202: 996
- 46.19.137.194: 476
- 178.20.210.32: 450
