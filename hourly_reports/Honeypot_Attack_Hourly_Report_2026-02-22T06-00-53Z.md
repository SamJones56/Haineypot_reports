
# Honeypot Attack Report - 2026-02-22T06:00:13Z

## Executive Summary:
- A total of 4212 attacks were observed in the last hour.
- The United States was the top attacking country with 1599 attacks.
- The most common alert category was "Generic Protocol Command Decode" with 593 occurrences.
- The most frequent alert signature was "SURICATA SSH invalid banner" (ID: 2228000) with 258 hits.
- The most active ASN was 14061 (DigitalOcean, LLC) with 1168 attacks.
- The most aggressive IP was 59.145.41.149 with 432 attacks.

## Detailed Analysis:

**Total Attacks:** 4212

**Top Attacking Countries:**
- United States: 1599
- India: 800
- Netherlands: 532
- Romania: 356
- Canada: 175

**Notable IP Reputations:**
- known attacker: 1618
- mass scanner: 123
- tor exit node: 4
- bot, crawler: 1

**Common Alert Categories:**
- Generic Protocol Command Decode: 593
- Misc activity: 503
- Misc Attack: 382
- Attempted Information Leak: 52
- Potentially Bad Traffic: 26

**Alert Signatures:**
- 2228000 - SURICATA SSH invalid banner: 258
- 2100560 - GPL INFO VNC server response: 222
- 2001984 - ET INFO SSH session in progress on Unusual Port: 118
- 2402000 - ET DROP Dshield Block Listed Source group 1: 107
- 2200003 - SURICATA IPv4 truncated packet: 103

**ASN Information:**
- 14061 - DigitalOcean, LLC: 1168
- 47890 - Unmanaged Ltd: 535
- 20473 - The Constant Company, LLC: 492
- 9498 - BHARTI Airtel Ltd.: 432
- 16509 - Amazon.com, Inc.: 238

**Source IP Addresses:**
- 59.145.41.149: 432
- 143.110.179.223: 360
- 142.93.234.28: 345
- 144.202.31.88: 289
- 129.212.184.194: 114

**Country to Port Mapping:**
- Canada:
  - 1025: 3
  - 4602: 3
  - 8916: 3
  - 1111: 2
  - 3458: 2
- India:
  - 445: 432
  - 22: 72
  - 23: 2
  - 8084: 2
  - 12000: 2
- Netherlands:
  - 22: 71
  - 23: 43
  - 27017: 42
  - 9100: 16
  - 17000: 8
- Romania:
  - 22: 63
  - 443: 3
  - 587: 2
  - 2113: 2
  - 4861: 2
- United States:
  - 2323: 158
  - 5902: 114
  - 23: 72
  - 5903: 57
  - 9093: 57

**CVEs Exploited:**
- CVE-2025-55182 CVE-2025-55182: 7
- CVE-2024-14007 CVE-2024-14007: 5
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2019-11500 CVE-2019-11500: 1

**Usernames:**
- root: 37
- mysql: 28
- git: 26
- hadoop: 26
- zabbix: 26
- postgres: 22
- solv: 17
- admin: 15
- gerrit: 14
- user: 8

**Passwords:**
- 123456: 18
- 123: 16
- 1234: 15
- 12345678: 15
- : 13

**OS Distribution:**
- Linux 2.2.x-3.x: 8837
- Linux 2.2.x-3.x (barebone): 333
- Windows NT kernel 5.x: 239
- Linux 3.11 and newer: 50
- Linux 2.2.x-3.x (no timestamps): 94

**Hyper-aggressive IPs:**
- 59.145.41.149: 432
- 143.110.179.223: 360
- 142.93.234.28: 345
- 144.202.31.88: 289
- 129.212.184.194: 114
