
# Honeypot Attack Report - 2026-02-23T08:00:23Z

## Executive Summary:
- A total of 5739 attacks were observed in the last hour.
- The majority of attacks originated from the United States (2395), followed by Germany (769) and India (475).
- The most prominent attacker ASN is 14061 (DigitalOcean, LLC) with 3878 attacks.
- The most common alert category is "Generic Protocol Command Decode" with 3972 instances.
- The most frequent alert signature is "SURICATA IPv4 truncated packet" with 1822 occurrences.
- A significant number of attackers (1894) are known attackers.

## Detailed Analysis:

**Total Attacks:**
- 5739

**Top Attacking Countries:**
- United States: 2395
- Germany: 769
- India: 475
- Singapore: 471
- Canada: 329

**Notable IP Reputations:**
- known attacker: 1894
- mass scanner: 259
- bot, crawler: 1

**Common Alert Categories:**
- Generic Protocol Command Decode: 3972
- Misc activity: 593
- Misc Attack: 374
- Attempted Information Leak: 99
- Attempted Administrator Privilege Gain: 26

**Alert Signatures:**
- 2200003: SURICATA IPv4 truncated packet - 1822
- 2200122: SURICATA AF-PACKET truncated packet - 1822
- 2100560: GPL INFO VNC server response - 216
- 2228000: SURICATA SSH invalid banner - 184
- 2001978: ET INFO SSH session in progress on Expected Port - 151

**ASN Information:**
- 14061: DigitalOcean, LLC - 3878
- 47890: Unmanaged Ltd - 437
- 131427: AOHOAVIET - 205
- 213412: ONYPHE SAS - 111
- 51852: Private Layer INC - 110

**Source IP Addresses:**
- 152.42.176.89: 467
- 64.227.14.127: 435
- 159.65.243.235: 407
- 162.243.218.184: 390
- 178.128.236.77: 315
- 167.71.239.213: 240
- 157.245.100.145: 233
- 64.226.101.160: 213
- 103.53.231.159: 205
- 138.197.178.172: 195

**Country to Port Mapping:**
- Canada:
  - 22: 54
  - 8728: 6
  - 30029: 3
  - 50008: 3
  - 7001: 1
- Germany:
  - 22: 139
  - 23: 15
  - 9299: 4
  - 46640: 4
  - 8332: 2
- India:
  - 22: 92
  - 23: 1
- Singapore:
  - 22: 86
  - 80: 2
  - 5901: 1
  - 5909: 1
- United States:
  - 22: 236
  - 5902: 112
  - 1194: 80
  - 5901: 59
  - 5903: 57

**CVEs Exploited:**
- CVE-2025-55182 CVE-2025-55182: 12
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2021-3449 CVE-2021-3449: 1
- CVE-2024-12856 CVE-2024-12856 CVE-2024-12885: 1

**Usernames:**
- root: 290
- admin: 142
- ubuntu: 46
- centos: 35
- user: 25
- mysql: 18
- test: 14
- backup: 13
- dspace: 12
- odoo: 12

**Passwords:**
- 123456: 49
- 12345678: 30
- 1234: 28
- password: 27
- 123: 26
- 12345: 24
- qwerty: 22
- 123456789: 19
- passw0rd: 17
- 111111: 16

**OS Distribution:**
- Linux 2.2.x-3.x: 16283
- Linux 2.2.x-3.x (barebone): 289
- Windows NT kernel 5.x: 136
- Linux 3.11 and newer: 41
- Linux 2.2.x-3.x (no timestamps): 166

**Hyper-aggressive IPs:**
- 152.42.176.89: 467
- 64.227.14.127: 435
- 159.65.243.235: 407
- 162.243.218.184: 390
- 178.128.236.77: 315
