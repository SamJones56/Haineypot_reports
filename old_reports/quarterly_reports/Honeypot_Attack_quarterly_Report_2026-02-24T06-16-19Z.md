# Honeypot Attack Report - 2026-02-24T06:15:20Z

## Executive Summary:
- Over 25,000 attacks were observed in the last 6 hours, with the United States, India, and France being the top attacking countries.
- The most prominent attacker IP, 203.194.103.78, was responsible for over 3,000 attacks, originating from India and associated with ONEOTT INTERTAINMENT LIMITED.
- "Generic Protocol Command Decode" was the most common alert category, with "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet" being the most frequent signatures.
- Brute force attacks on SSH and VNC services were common, with "root" and "admin" as the most targeted usernames and "123456" and "password" as the most used passwords.
- The majority of attacks originated from systems running the Linux operating system.
- Several CVEs were exploited, with CVE-2006-2369 being the most frequent.

## Detailed Analysis:

**Total Attacks:**
- 25584

**Top Attacking Countries:**
- United States: 8135
- India: 3180
- France: 2321
- United Kingdom: 2098
- Romania: 1153

**Notable IP Reputations:**
- known attacker: 10991
- bot, crawler: 1623
- mass scanner: 794
- tor exit node: 1

**Common Alert Categories:**
- Generic Protocol Command Decode: 9512
- Misc activity: 2754
- Misc Attack: 1987
- Attempted Information Leak: 407
- Potentially Bad Traffic: 133

**Alert Signatures:**
- 2200003, SURICATA IPv4 truncated packet: 3358
- 2200122, SURICATA AF-PACKET truncated packet: 3358
- 2100560, GPL INFO VNC server response: 1406
- 2228000, SURICATA SSH invalid banner: 1232
- 2402000, ET DROP Dshield Block Listed Source group 1: 635

**ASN Information:**
- 14061, DigitalOcean, LLC: 5300
- 17665, ONEOTT INTERTAINMENT LIMITED: 3147
- 211590, Bucklog SARL: 2268
- 47890, Unmanaged Ltd: 1949
- 396982, Google LLC: 1189

**Source IP Addresses:**
- 203.194.103.78: 3147
- 157.245.36.181: 1896
- 185.177.72.23: 1793
- 127.0.0.1: 1620
- 162.243.37.252: 1426

**Country to Port Mapping:**
- France
  - 80: 2268
  - 3128: 16
  - 5900: 5
  - 25565: 3
  - 22: 2
- India
  - 445: 3147
  - 22: 4
  - 23: 2
  - 2375: 2
  - 2376: 2
- Romania
  - 22: 178
  - 587: 8
  - 443: 6
  - 1900: 2
  - 1960: 2
- United Kingdom
  - 22: 376
  - 80: 12
  - 443: 11
  - 9810: 8
  - 9812: 8
- United States
  - 5902: 666
  - 5901: 361
  - 5903: 337
  - 22: 321
  - 1494: 117

**CVEs Exploited:**
- CVE-2006-2369: 64
- CVE-2024-14007 CVE-2024-14007: 28
- CVE-2019-11500 CVE-2019-11500: 7
- CVE-2025-55182 CVE-2025-55182: 6
- CVE-2021-3449 CVE-2021-3449: 5

**Usernames:**
- root: 180
- admin: 173
- daemon: 125
- test: 106
- user: 83
- ubuntu: 59
- mysql: 39
- oracle: 37
- guest: 36
- postgres: 31

**Passwords:**
- 123456: 76
- password: 70
- 12345678: 60
- 12345: 35
- 1234: 34

**OS Distribution:**
- Linux 2.2.x-3.x: 76348
- Windows NT kernel: 49465
- Linux 3.1-3.10: 3397
- Linux 3.11 and newer: 3314
- Linux 3.x: 1129

**Hyper-aggressive IPs:**
- 203.194.103.78: 3147
- 157.245.36.181: 1896
- 185.177.72.23: 1793
- 162.243.37.252: 1426
