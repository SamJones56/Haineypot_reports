# Honeypot Attack Report - 2026-02-20T10:00:21Z

## Executive Summary:
- **High Attack Volume:** A total of 4,493 attacks were observed in the past hour, with the majority originating from the United States and Germany.
- **Dominant Attacker:** The most aggressive IP address was 173.73.62.72, with 796 attacks, associated with Verizon Business.
- **VNC Scanning:** The most frequent alert signature was "GPL INFO VNC server response," indicating widespread scanning for open VNC servers.
- **Common Credentials:** Brute-force attempts commonly used default credentials like "root" and "admin" with simple passwords such as "password" and "123456".
- **Operating System Distribution:** The primary attacking operating systems were identified as Windows NT kernel and Linux 2.2.x-3.x.
- **Known Attackers:** A significant portion of the attacks (1,095) originated from IP addresses with a reputation as "known attacker".

## Detailed Analysis:

### Total Attacks:
- 4,493

### Top Attacking Countries:
- United States: 1,386
- Germany: 1,000
- Singapore: 388
- Netherlands: 324
- United Kingdom: 296

### Notable IP Reputations:
- known attacker: 1,095
- mass scanner: 200
- bot, crawler: 5

### Common Alert Categories:
- Misc activity: 2,435
- Generic Protocol Command Decode: 602
- Misc Attack: 431
- Attempted Information Leak: 73
- Potentially Bad Traffic: 21
- Attempted Administrator Privilege Gain: 14
- Detection of a Network Scan: 6
- Detection of a Denial of Service Attack: 3
- Not Suspicious Traffic: 3
- A Network Trojan was detected: 2

### Alert Signatures:
- 2100560 - GPL INFO VNC server response: 2,306
- 2200003 - SURICATA IPv4 truncated packet: 212
- 2200122 - SURICATA AF-PACKET truncated packet: 212
- 2402000 - ET DROP Dshield Block Listed Source group 1: 112
- 2001978 - ET INFO SSH session in progress on Expected Port: 63
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 41
- 2009582 - ET SCAN NMAP -sS window 1024: 40
- 2228000 - SURICATA SSH invalid banner: 28
- 2210051 - SURICATA STREAM Packet with broken ack: 26
- 2023753 - ET SCAN MS Terminal Server Traffic on Non-standard Port: 24

### ASN Information:
- 14061 - DigitalOcean, LLC: 1,583
- 701 - Verizon Business: 796
- 8075 - Microsoft Corporation: 405
- 151729 - SWIFTIFY PRIVATE LIMITED: 262
- 209334 - Modat B.V.: 164
- 396982 - Google LLC: 158
- 16509 - Amazon.com, Inc.: 131
- 51852 - Private Layer INC: 109
- 213412 - ONYPHE SAS: 108
- 6939 - Hurricane Electric LLC: 59

### Source IP Addresses:
- 173.73.62.72: 796
- 4.145.113.4: 388
- 164.90.185.60: 350
- 206.189.61.203: 266
- 103.72.9.82: 262
- 167.99.218.227: 210
- 144.126.205.38: 199
- 206.81.21.204: 192
- 46.101.240.14: 160
- 170.64.175.89: 150

### Country to Port Mapping:
- **Australia**:
  - 22: 30
- **Canada**:
  - 8728: 8
  - 1337: 5
  - 3522: 3
  - 2812: 2
  - 5154: 2
- **China**:
  - 5905: 24
  - 4063: 8
  - 22: 6
  - 2223: 4
  - 9020: 4
- **Germany**:
  - 22: 175
  - 1302: 7
  - 2776: 4
  - 3306: 4
  - 8243: 4
- **India**:
  - 23: 133
- **Netherlands**:
  - 22: 48
  - 27017: 21
  - 80: 19
  - 9100: 16
  - 3128: 5
- **Singapore**:
  - 5901: 39
  - 5902: 39
  - 5904: 39
  - 5906: 39
  - 5907: 39
- **Switzerland**:
  - 5434: 108
  - 5432: 1
- **United Kingdom**:
  - 22: 33
  - 9000: 13
  - 8090: 10
  - 8663: 2
  - 18015: 2
- **United States**:
  - 445: 796
  - 8728: 28
  - 6379: 26
  - 8089: 19
  - 50105: 18

### CVEs Exploited:
- CVE-2021-3449
- CVE-2019-11500
- CVE-2006-2369
- CVE-2024-14007
- CVE-2025-55182

### Usernames:
- root: 113
- admin: 28
- backup: 22
- postgres: 19
- oracle: 18
- user: 18
- daemon: 13
- es: 11
- ftptest: 11
- pi: 10

### Passwords:
- password: 19
- password1: 14
- 12345: 13
- 123456: 13
- 123: 11
- 1234: 11
- 12345678: 11
- 123456789: 11
- 010481: 10
- 1q2w3e4r: 10

### OS Distribution:
- Windows NT kernel: 17,051
- Linux 2.2.x-3.x: 16,016
- Windows NT kernel 5.x: 9,127
- Windows 7 or 8: 844
- Linux 2.2.x-3.x (barebone): 267
- Linux 2.2.x-3.x (no timestamps): 93
- Linux 3.11 and newer: 42
- Mac OS X: 24
- FreeBSD: 3
- Linux 3.1-3.10: 2

### Hyper-aggressive IPs:
- 173.73.62.72: 796 attacks
- 4.145.113.4: 388 attacks
- 164.90.185.60: 350 attacks
- 206.189.61.203: 266 attacks
- 103.72.9.82: 262 attacks
