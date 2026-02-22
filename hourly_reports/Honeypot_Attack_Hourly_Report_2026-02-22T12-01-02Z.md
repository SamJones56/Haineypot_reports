# Honeypot Attack Report - 2026-02-22T12:00:18Z

## Executive Summary:
- **High Volume of Attacks**: A total of 4734 attacks were observed in the past hour, indicating a significant level of malicious activity.
- **Dominant Attacker**: The IP address 139.59.62.156, associated with DigitalOcean LLC (ASN 14061) in India, was the most aggressive attacker, responsible for 1164 attacks.
- **Geographic Distribution**: India and the United States were the top two attacking countries, contributing 1621 and 1229 attacks respectively.
- **Common Tactics**: The most frequent alert category was "Generic Protocol Command Decode" with 692 instances. Brute-force attempts were prevalent, with "root" being the most targeted username (164 attempts).
- **Vulnerability Exploitation**: Several CVEs were targeted, with CVE-2025-55182 being the most frequent.
- **Operating System Landscape**: The majority of attacking systems were identified as Linux-based, with "Linux 2.2.x-3.x" appearing 12391 times.

## Detailed Analysis:

### Total Attacks:
4734

### Top Attacking Countries:
- India: 1621
- United States: 1229
- United Kingdom: 414
- Romania: 331
- Germany: 330

### Notable IP Reputations:
- known attacker: 1439
- mass scanner: 135

### Common Alert Categories:
- Generic Protocol Command Decode: 692
- Misc activity: 494
- Misc Attack: 291
- Attempted Information Leak: 253
- Attempted Administrator Privilege Gain: 31

### Alert Signatures:
- 2100560, GPL INFO VNC server response: 226
- 2228000, SURICATA SSH invalid banner: 220
- 2023753, ET SCAN MS Terminal Server Traffic on Non-standard Port: 176
- 2200003, SURICATA IPv4 truncated packet: 161
- 2200122, SURICATA AF-PACKET truncated packet: 161

### ASN Information:
- 14061, DigitalOcean, LLC: 2069
- 9498, BHARTI Airtel Ltd.: 370
- 20473, The Constant Company, LLC: 343
- 47890, Unmanaged Ltd: 339
- 396982, Google LLC: 263

### Source IP Addresses:
- 139.59.62.156: 1164
- 59.145.41.149: 370
- 159.65.92.74: 309
- 178.20.210.32: 176
- 129.212.184.194: 113

### Country to Port Mapping:
- **Germany**:
  - 22: 54
  - 1446: 4
  - 2000: 4
  - 5357: 4
  - 6609: 4
- **India**:
  - 445: 370
  - 22: 231
  - 23: 39
- **Romania**:
  - 22: 42
  - 11111: 8
  - 22222: 8
  - 33389: 8
  - 33895: 8
- **United Kingdom**:
  - 22: 54
  - 80: 2
  - 443: 2
  - 1308: 2
  - 3000: 2
- **United States**:
  - 5902: 114
  - 4433: 88
  - 5903: 58
  - 5901: 54
  - 4443: 48

### CVEs Exploited:
- CVE-2025-55182 CVE-2025-55182: 6
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2019-11500 CVE-2019-11500: 1

### Usernames:
- root: 164
- ubuntu: 33
- admin: 32
- xbmc: 26
- postgres: 20
- test: 15
- user: 10
- apache: 9
- oracle: 8
- ftp: 7

### Passwords:
- 123456: 50
- password: 21
- : 12
- root: 9
- P@ssw0rd: 8

### OS Distribution:
- Linux 2.2.x-3.x: 12391
- Windows NT kernel: 10098
- Linux 2.2.x-3.x (barebone): 391
- Windows NT kernel 5.x: 128
- Linux 2.2.x-3.x (no timestamps): 214

### Hyper-aggressive IPs:
- 139.59.62.156: 1164
