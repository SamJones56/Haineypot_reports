# Honeypot Attack Report - 2026-02-22T20:00:20Z

## Executive Summary:
- **High Attack Volume:** A total of 6,826 attacks were observed in the past hour, indicating a significant level of malicious activity.
- **Geographic Concentration:** The majority of attacks originated from the United States (1,854), United Kingdom (1,675), and Qatar (1,142), suggesting targeted campaigns from these regions.
- **Dominant Aggressor:** A single IP address, 178.153.127.226, from Qatar, was responsible for 1,142 attacks, demonstrating hyper-aggressive behavior targeting port 445.
- **Common Vulnerabilities:** Brute-force attempts were prevalent, with "root" and "admin" as the most common usernames. Additionally, several CVEs were exploited, with CVE-2002-0953 being the most frequent.
- **Signature Analysis:** The most common alert signature was "GPL INFO VNC server response," indicating a focus on reconnaissance and exploitation of VNC services.
- **Attacker Infrastructure:** DigitalOcean, LLC was the top ASN, hosting a significant portion of the attack infrastructure.

## Detailed Analysis:

**Total Attacks:**
- 6,826

**Top Attacking Countries:**
- United States: 1,854
- United Kingdom: 1,675
- Qatar: 1,142
- Germany: 638
- India: 354

**Notable IP Reputations:**
- known attacker: 1,617
- mass scanner: 76
- bot, crawler: 1

**Common Alert Categories:**
- Generic Protocol Command Decode: 588
- Misc activity: 574
- Misc Attack: 212
- Attempted Information Leak: 63
- A Network Trojan was detected: 36

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 228
- 2228000 - SURICATA SSH invalid banner: 203
- 2001978 - ET INFO SSH session in progress on Expected Port: 152
- 2200003 - SURICATA IPv4 truncated packet: 120
- 2200122 - SURICATA AF-PACKET truncated packet: 120

**ASN Information:**
- 14061, DigitalOcean, LLC: 3,649
- 8781, Ooredoo Q.S.C.: 1,142
- 47890, Unmanaged Ltd: 341
- 210006, Shereverov Marat Ahmedovich: 335
- 8075, Microsoft Corporation: 220

**Source IP Addresses:**
- 178.153.127.226: 1,142
- 161.35.39.52: 468
- 142.93.39.124: 406
- 167.172.56.108: 394
- 159.65.61.59: 371

**Country to Port Mapping:**
- **Germany**
  - 22: 112
  - 23: 15
  - 80: 4
  - 2999: 4
  - 6778: 4
- **India**
  - 22: 68
  - 25: 2
  - 2222: 2
- **Qatar**
  - 445: 1,142
- **United Kingdom**
  - 22: 311
  - 5432: 3
  - 27017: 2
  - 1754: 1
  - 9000: 1
- **United States**
  - 22: 182
  - 5902: 115
  - 5903: 57
  - 5901: 55
  - 8728: 28

**CVEs Exploited:**
- CVE-2002-0953: 8
- CVE-2024-14007 CVE-2024-14007: 5
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2025-55182 CVE-2025-55182: 2

**Usernames:**
- root: 227
- admin: 127
- postgres: 112
- mysql: 38
- oracle: 32
- user: 26
- test: 19
- apache: 12
- docker: 11
- administrator: 10

**Passwords:**
- 123456: 44
- password: 31
- 123: 29
- 1234: 27
- 12345678: 27

**OS Distribution:**
- Linux 2.2.x-3.x: 17,636
- Windows NT kernel: 2,141
- Linux 2.2.x-3.x (barebone): 355
- Windows NT kernel 5.x: 77
- Linux 2.2.x-3.x (no timestamps): 286

**Hyper-aggressive IPs:**
- 178.153.127.226: 1,142 attacks

**Other Notable Deviations:**
- **High Concentration Patterns:** A single IP from Qatar (178.153.127.226) was responsible for all 1,142 attacks from that country, all targeting port 445. This suggests a highly targeted and automated attack from a single source.