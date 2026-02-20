# Honeypot Attack Report - 2026-02-20T05:00:14Z

## Executive Summary:
- Over 2,600 attacks were detected in the past hour, with the United States and Germany being the most prominent sources.
- DigitalOcean, LLC was the top attacking ASN, with its associated IP, 138.68.109.50, being the most aggressive source.
- The most frequent alert category was "Generic Protocol Command Decode," with "SURICATA IPv4 truncated packet" being the most common signature.
- A number of older CVEs were targeted, including CVE-2002-0606 and CVE-2006-2369.
- Brute-force attempts were common, with "root" and "admin" as the most targeted usernames.
- The majority of attacking systems were identified as running Windows NT kernel.

## Detailed Analysis:

**Total Attacks:**
- 2615

**Top Attacking Countries:**
- United States: 873
- Germany: 505
- Singapore: 354
- United Kingdom: 184
- China: 113

**Notable IP Reputations:**
- known attacker: 1137
- mass scanner: 238
- compromised: 11

**Common Alert Categories:**
- Generic Protocol Command Decode: 13064
- Misc activity: 2147
- Misc Attack: 383
- Attempted Information Leak: 100
- Potentially Bad Traffic: 46

**Alert Signatures:**
- 2200003 - SURICATA IPv4 truncated packet: 6450
- 2200122 - SURICATA AF-PACKET truncated packet: 6450
- 2100560 - GPL INFO VNC server response: 2084
- 2402000 - ET DROP Dshield Block Listed Source group 1: 101
- 2210051 - SURICATA STREAM Packet with broken ack: 58

**ASN Information:**
- 14061 - DigitalOcean, LLC: 837
- 8075 - Microsoft Corporation: 366
- 174 - Cogent Communications, LLC: 200
- 396982 - Google LLC: 173
- 213412 - ONYPHE SAS: 96

**Source IP Addresses:**
- 138.68.109.50: 445
- 4.145.113.4: 348
- 46.19.137.194: 71
- 134.209.183.113: 66
- 85.217.149.12: 59

**Country to Port Mapping:**
- **China**
  - 23: 25
  - 5905: 20
  - 1433: 16
- **Germany**
  - 22: 86
  - 20793: 4
  - 34079: 4
- **Singapore**
  - 5902: 35
  - 5903: 35
  - 5904: 35
- **United Kingdom**
  - 22: 10
  - 1025: 6
  - 6070: 3
- **United States**
  - 9200: 20
  - 22: 11
  - 9443: 8

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 2
- CVE-2002-0606: 1
- CVE-2006-2369: 1
- CVE-2018-10562 CVE-2018-10561: 1
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- root: 73
- admin: 20
- sa: 15
- ubuntu: 10
- test: 4
- customer: 2
- postgres: 1
- testing123: 1
- user: 1

**Passwords:**
- 123456: 7
- password: 7
- : 6
- 123456789: 4
- 123: 3

**OS Distribution:**
- Windows NT kernel: 15778
- Windows NT kernel 5.x: 9018
- Linux 2.2.x-3.x: 7539
- Linux 2.2.x-3.x (barebone): 470
- Linux 3.11 and newer: 30

**Hyper-aggressive IPs:**
- 138.68.109.50: 445
- 4.145.113.4: 348
