# Honeypot Attack Report - 2026-02-22T10:00:13Z

## Executive Summary:
- Over 3,500 attacks were observed in the past hour, with the United States being the most prominent source country, accounting for nearly half of all attacks.
- The most aggressive attacker IP, 139.59.62.156, which is associated with DigitalOcean, was responsible for over 20% of the total attack volume.
- SSH and VNC services were heavily targeted, with "SURICATA SSH invalid banner" and "GPL INFO VNC server response" being the most frequent alert signatures.
- Brute-force attempts were common, with "root" and "admin" being the most used usernames and "123456" and "password" the most common passwords.
- The majority of attacking systems appear to be running Linux-based operating systems.
- Several CVEs were targeted, with CVE-2023-46604 being the most frequently exploited.

## Detailed Analysis:

### Total Attacks:
- 3540

### Top Attacking Countries:
- United States: 1549
- India: 794
- Australia: 256
- Germany: 255
- United Kingdom: 132

### Notable IP Reputations:
- known attacker: 1196
- mass scanner: 136
- bot, crawler: 1
- tor exit node: 1

### Common Alert Categories:
- Misc activity: 500
- Generic Protocol Command Decode: 477
- Misc Attack: 341
- Attempted Information Leak: 82
- Potentially Bad Traffic: 16

### Alert Signatures:
- 2228000 - SURICATA SSH invalid banner: 258
- 2100560 - GPL INFO VNC server response: 232
- 2001984 - ET INFO SSH session in progress on Unusual Port: 121
- 2402000 - ET DROP Dshield Block Listed Source group 1: 98
- 2001978 - ET INFO SSH session in progress on Expected Port: 75

### ASN Information:
- 14061 (DigitalOcean, LLC): 1983
- 47890 (Unmanaged Ltd): 303
- 16509 (Amazon.com, Inc.): 227
- 396982 (Google LLC): 128
- 201002 (PebbleHost Ltd): 73

### Source IP Addresses:
- 139.59.62.156: 756
- 165.22.2.4: 430
- 209.38.28.196: 256
- 46.101.214.86: 161
- 129.212.184.194: 113

### Country to Port Mapping:
- **Australia**
  - 22: 47
- **Germany**
  - 22: 38
  - 80: 11
  - 26997: 4
- **India**
  - 22: 156
- **United Kingdom**
  - 5068: 4
  - 80: 3
  - 1071: 2
- **United States**
  - 5902: 114
  - 22: 105
  - 5901: 56

### CVEs Exploited:
- CVE-2023-46604
- CVE-2021-3449
- CVE-2019-11500
- CVE-2024-14007
- CVE-2025-55182

### Usernames:
- root: 64
- guest: 45
- user: 31
- admin: 30
- test: 28
- deploy: 13
- alex: 5
- bot: 5
- ftp: 5
- git: 5

### Passwords:
- 123456: 28
- 123: 16
- 12345: 11
- password: 11
- admin: 10

### OS Distribution:
- Linux 2.2.x-3.x: 11908
- Linux 2.2.x-3.x (barebone): 273
- Windows NT kernel 5.x: 180
- Linux 2.2.x-3.x (no timestamps): 107
- Linux 3.11 and newer: 47

### Hyper-aggressive IPs:
- 139.59.62.156: 756
- 165.22.2.4: 430
- 209.38.28.196: 256
