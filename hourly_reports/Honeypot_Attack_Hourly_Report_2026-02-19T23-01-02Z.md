# Honeypot Attack Report - 2026-02-19T23:00:14Z

## Executive Summary:
- High volume of attacks (8762) in the last hour.
- Vietnam is the dominant source country, with one IP (103.237.145.16) from "Long Van Soft Solution JSC" accounting for the majority of attacks.
- "GPL INFO VNC server response" is the most frequent alert signature.
- Brute force attempts on SSH are common, with "root" being the most targeted username.
- The attacking systems are predominantly identified as Linux.

## Detailed Analysis:

### Total Attacks:
- 8762

### Top Attacking Countries:
- Vietnam: 5428
- United States: 981
- Singapore: 663
- India: 522
- Germany: 448

### Notable IP Reputations:
- known attacker: 6763
- mass scanner: 164

### Common Alert Categories:
- Misc activity: 2474
- Generic Protocol Command Decode: 462
- Misc Attack: 404
- Attempted Information Leak: 52
- Potentially Bad Traffic: 34

### Alert Signatures:
- 2100560 - GPL INFO VNC server response: 2322
- 2200003 - SURICATA IPv4 truncated packet: 154
- 2200122 - SURICATA AF-PACKET truncated packet: 154
- 2402000 - ET DROP Dshield Block Listed Source group 1: 128
- 2001978 - ET INFO SSH session in progress on Expected Port: 73

### ASN Information:
- 131414 - Long Van Soft Solution JSC: 5415
- 14061 - DigitalOcean, LLC: 1471
- 8075 - Microsoft Corporation: 412
- 396982 - Google LLC: 211
- 174 - Cogent Communications, LLC: 200

### Source IP Addresses:
- 103.237.145.16: 5415
- 139.59.82.171: 520
- 207.154.211.38: 420
- 4.145.113.4: 386
- 167.172.67.78: 271

### Country to Port Mapping:
- Germany
  - 22: 84
  - 10429: 4
  - 37777: 4
  - 62503: 4
  - 1444: 3
- India
  - 22: 104
  - 8090: 2
- Singapore
  - 22: 51
  - 5901: 39
  - 5904: 39
  - 5906: 39
  - 5907: 39
- United States
  - 27019: 35
  - 8728: 14
  - 15001: 12
  - 9097: 10
  - 5986: 9
- Vietnam
  - 22: 1085

### CVEs Exploited:
- CVE-2025-55182 CVE-2025-55182: 4
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2006-2369: 2
- CVE-2010-0569: 2
- CVE-2019-11500 CVE-2019-11500: 2

### Usernames:
- root: 1145
- dev: 13
- developer: 13
- docker: 13
- dspace: 13
- elastic: 13
- sa: 13
- elasticsearch: 10
- administrator: 9
- backup: 9

### Passwords:
- 123456: 22
- password: 22
- 123456789: 20
- 12345: 19
- 12345678: 19

### OS Distribution:
- Linux 2.2.x-3.x: 10170
- Windows NT kernel 5.x: 9213
- Linux 2.2.x-3.x (barebone): 491
- Linux 3.11 and newer: 28
- Linux 2.2.x-3.x (no timestamps): 26

### Hyper-aggressive IPs:
- 103.237.145.16: 5415
- 139.59.82.171: 520
- 207.154.211.38: 420
- 4.145.113.4: 386
- 167.172.67.78: 271
