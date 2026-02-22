# Honeypot Attack Report - 2026-02-22T11:00:14Z

## Executive Summary:
- A total of 4514 attacks were observed in the past hour.
- India and the United States were the top attacking countries, accounting for over 60% of the total attacks.
- The most prominent attacker IP was 139.59.62.156, with 1197 attacks.
- "Misc activity" and "Generic Protocol Command Decode" were the most common alert categories.
- The most common operating system identified was Linux 2.2.x-3.x.
- There were multiple hyper-aggressive IPs with more than 200 attacks each.

## Detailed Analysis:

**Total Attacks:**
- 4514

**Top Attacking Countries:**
- India: 1567
- United States: 1152
- Australia: 320
- Germany: 276
- Netherlands: 257

**Notable IP Reputations:**
- known attacker: 1695
- mass scanner: 105
- bot, crawler: 1

**Common Alert Categories:**
- Misc activity: 523
- Generic Protocol Command Decode: 506
- Misc Attack: 330
- Attempted Information Leak: 141
- Potentially Bad Traffic: 12

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 228
- 2228000 - SURICATA SSH invalid banner: 218
- 2001984 - ET INFO SSH session in progress on Unusual Port: 110
- 2001978 - ET INFO SSH session in progress on Expected Port: 82
- 2402000 - ET DROP Dshield Block Listed Source group 1: 80

**ASN Information:**
- 14061 - DigitalOcean, LLC: 2073
- 9498 - BHARTI Airtel Ltd.: 370
- 47890 - Unmanaged Ltd: 358
- 396982 - Google LLC: 342
- 16509 - Amazon.com, Inc.: 193

**Source IP Addresses:**
- 139.59.62.156: 1197
- 59.145.41.149: 370
- 209.38.28.196: 320
- 46.101.214.86: 223
- 34.158.168.101: 198

**Country to Port Mapping:**
- Australia:
  - 22: 64
- Germany:
  - 22: 44
  - 6609: 4
  - 6778: 4
  - 8009: 4
  - 16840: 4
- India:
  - 445: 370
  - 22: 239
- Netherlands:
  - 443: 196
  - 3478: 8
  - 25: 7
  - 22: 6
  - 80: 3
- United States:
  - 5902: 113
  - 5901: 58
  - 5903: 57
  - 8008: 42
  - 2181: 37

**CVEs Exploited:**
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2021-3449 CVE-2021-3449: 1
- CVE-2024-14007 CVE-2024-14007: 1
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- root: 41
- admin: 28
- oracle: 21
- ubuntu: 19
- guest: 12
- test: 11
- pi: 10
- postgres: 10
- user: 10
- minecraft: 8

**Passwords:**
- 123456: 57
- password: 14
- admin: 9
- : 6
- 1234: 6

**OS Distribution:**
- Linux 2.2.x-3.x: 12740
- Linux 2.2.x-3.x (barebone): 288
- Windows NT kernel 5.x: 129
- Linux 2.2.x-3.x (no timestamps): 153
- Linux 3.11 and newer: 41

**Hyper-aggressive IPs:**
- 139.59.62.156: 1197
- 59.145.41.149: 370
- 209.38.28.196: 320
- 46.101.214.86: 223
