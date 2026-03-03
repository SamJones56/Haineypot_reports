# Honeypot Attack Report - 2026-02-19T22:00:12Z

## Executive Summary:
- High attack volume this hour, with 8,877 total attacks recorded.
- The majority of attacks originated from Vietnam (5,987 attacks), representing a significant concentration from a single country.
- A single IP address, 103.237.145.16, associated with "Long Van Soft Solution JSC" in Vietnam, was hyper-aggressive, launching 5,980 attacks.
- "GPL INFO VNC server response" was the most frequent alert signature, indicating VNC service discovery or connection attempts.
- Brute-force activity was significant, with "root" being the most attempted username.
- Multiple CVEs were targeted, including CVE-2024-14007, CVE-2025-55182, and older vulnerabilities like CVE-2002-0012/13.

## Detailed Analysis:

**Total Attacks:**
- 8877

**Top Attacking Countries:**
- Vietnam: 5987
- United States: 910
- India: 464
- Singapore: 433
- Germany: 280

**Notable IP Reputations:**
- known attacker: 7180
- mass scanner: 184

**Common Alert Categories:**
- Misc activity: 2440
- Generic Protocol Command Decode: 1729
- Misc Attack: 395
- Potentially Bad Traffic: 86
- Attempted Information Leak: 52

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 2320
- 2200003 - SURICATA IPv4 truncated packet: 705
- 2200122 - SURICATA AF-PACKET truncated packet: 705
- 2210048 - SURICATA STREAM reassembly sequence GAP -- missing packet(s): 172
- 2402000 - ET DROP Dshield Block Listed Source group 1: 113

**ASN Information:**
- 131414 - Long Van Soft Solution JSC: 5980
- 14061 - DigitalOcean, LLC: 1082
- 8075 - Microsoft Corporation: 411
- 396982 - Google LLC: 257
- 174 - Cogent Communications, LLC: 211

**Source IP Addresses:**
- 103.237.145.16: 5980
- 4.145.113.4: 385
- 139.59.82.171: 358
- 207.154.211.38: 225
- 146.190.169.67: 117

**Country to Port Mapping:**
- **Germany**
  - 22: 49
  - 7443: 4
  - 3115: 3
- **India**
  - 22: 89
  - 25: 3
  - 8883: 1
- **Singapore**
  - 5901: 39
  - 5902: 39
  - 5903: 39
- **United States**
  - 22: 23
  - 80: 17
  - 1241: 10
- **Vietnam**
  - 22: 1198

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007
- CVE-2025-55182 CVE-2025-55182
- CVE-2002-0013 CVE-2002-0012

**Usernames:**
- root: 1220
- sa: 60
- ubuntu: 36
- admin: 32
- oracle: 22
- postgres: 20
- test: 16
- backup: 13
- daemon: 13
- guest: 8

**Passwords:**
- password: 18
- 12345: 15
- 123456: 15
- 12345678: 15
- 123456789: 14

**OS Distribution:**
- Linux 2.2.x-3.x: 13666
- Windows NT kernel 5.x: 9632
- Linux 2.2.x-3.x (barebone): 481
- Linux 3.11 and newer: 61
- Linux 2.2.x-3.x (no timestamps): 32

**Hyper-aggressive IPs:**
- 103.237.145.16: 5980 attacks

**Other Notable Deviations:**
- High concentration of attacks from a single source IP (103.237.145.16) originating from Vietnam.
- Singapore-based IPs show a distinct pattern of scanning VNC-related ports (5901, 5902, 5903).
