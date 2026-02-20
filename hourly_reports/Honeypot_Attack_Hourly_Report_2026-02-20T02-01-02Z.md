# Honeypot Attack Report - 2026-02-20T02:00:13Z

## Executive Summary:
- A high volume of attacks (9,441) were observed in the past hour, with a significant concentration from a single IP address in Vietnam.
- The dominant attacker (103.237.145.16), associated with Long Van Soft Solution JSC in Vietnam, was responsible for 6,161 attacks, indicating a targeted campaign.
- The most frequent alert signature was "GPL INFO VNC server response," suggesting widespread scanning for remote desktop vulnerabilities.
- Brute-force activity was prominent, with "root" being the most commonly attempted username.
- A small number of CVEs were targeted, including CVE-2024-14007.
- The majority of attacking systems were identified as running Windows, followed closely by Linux.

## Detailed Analysis:

### Total Attacks:
- 9,441

### Top Attacking Countries:
- Vietnam: 6,161
- United States: 1,535
- India: 456
- Singapore: 440
- Canada: 159

### Notable IP Reputations:
- known attacker: 7,366
- mass scanner: 266
- bot, crawler: 2

### Common Alert Categories:
- Generic Protocol Command Decode: 3,344
- Misc activity: 2,490
- Misc Attack: 509
- Potentially Bad Traffic: 86
- Attempted Information Leak: 65

### Alert Signatures:
- 2100560 - GPL INFO VNC server response: 2,322
- 2200003 - SURICATA IPv4 truncated packet: 1,594
- 2200122 - SURICATA AF-PACKET truncated packet: 1,594
- 2402000 - ET DROP Dshield Block Listed Source group 1: 217
- 2001978 - ET INFO SSH session in progress on Expected Port: 62

### ASN Information:
- 131414 - Long Van Soft Solution JSC: 6,161
- 14061 - DigitalOcean, LLC: 1,267
- 8075 - Microsoft Corporation: 412
- 396982 - Google LLC: 275
- 209334 - Modat B.V.: 151

### Source IP Addresses:
- 103.237.145.16: 6,161
- 64.227.172.219: 456
- 4.145.113.4: 383
- 159.203.105.250: 369
- 137.184.196.109: 147

### Country to Port Mapping:
- **Canada**:
  - 8728: 4
  - 1214: 2
  - 4000: 2
- **India**:
  - 22: 88
- **Singapore**:
  - 5903: 39
  - 5905: 39
  - 5910: 39
- **United States**:
  - 22: 70
  - 6379: 22
  - 8081: 14
- **Vietnam**:
  - 22: 1,232

### CVEs Exploited:
- CVE-2024-14007
- CVE-2019-11500
- CVE-2025-55182

### Usernames:
- root: 1,315
- sa: 57
- admin: 16
- backup: 13
- daemon: 13

### Passwords:
- admin123: 12
- 12345: 10
- 123456789: 10
- password: 10
- 123456: 9

### OS Distribution:
- Linux 2.2.x-3.x: 8,384
- Windows NT kernel 5.x: 9,838
- Linux 2.2.x-3.x (barebone): 536
- Windows NT kernel: 512
- Linux 2.2.x-3.x (no timestamps): 102

### Hyper-aggressive IPs:
- 103.237.145.16: 6,161 attacks
