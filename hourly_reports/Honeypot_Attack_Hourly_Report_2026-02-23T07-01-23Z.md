# Honeypot Attack Report - 2026-02-23T07:00:26Z

## Executive Summary:
- **High Volume Attack Activity:** A total of 6,796 attacks were observed in the past hour, indicating a significant level of malicious activity.
- **Dominant Attacker Origin:** The United States was the most prominent source of attacks, accounting for 2,644 incidents, followed by India and Australia.
- **DigitalOcean, LLC ASN Dominance:** A large portion of attacks (4,903) originated from the ASN 14061, registered to DigitalOcean, LLC.
- **SSH and VNC Focus:** The most frequent alert signatures were related to SSH and VNC protocols, with "SURICATA SSH invalid banner" and "GPL INFO VNC server response" being the top two.
- **Common Credentials Targeted:** Brute-force attempts commonly used default or simple credentials, with "root", "oracle", and "guest" as the top usernames, and "123456" and "password" as the most used passwords.
- **Linux-Based Attackers:** The overwhelming majority of attacking systems were identified as running Linux-based operating systems.

## Detailed Analysis:

**Total Attacks:**
- 6796

**Top Attacking Countries:**
- United States: 2644
- India: 1315
- Australia: 778
- Canada: 617
- Germany: 332

**Notable IP Reputations:**
- known attacker: 1159
- mass scanner: 264

**Common Alert Categories:**
- Misc activity: 659
- Generic Protocol Command Decode: 558
- Misc Attack: 416
- Attempted Information Leak: 114
- Attempted Administrator Privilege Gain: 29

**Alert Signatures:**
- 2228000 - SURICATA SSH invalid banner: 227
- 2100560 - GPL INFO VNC server response: 216
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 173
- 2402000 - ET DROP Dshield Block Listed Source group 1: 165
- 2001978 - ET INFO SSH session in progress on Expected Port: 150

**ASN Information:**
- 14061, DigitalOcean, LLC: 4903
- 47890, Unmanaged Ltd: 355
- 131427, AOHOAVIET: 215
- 213412, ONYPHE SAS: 118
- 396982, Google LLC: 111

**Source IP Addresses:**
- 157.245.101.183: 705
- 165.227.118.67: 554
- 192.241.189.141: 515
- 138.197.136.0: 486
- 170.64.152.98: 425

**Country to Port Mapping:**
- **Australia**
  - 22: 151
  - 23: 1
- **Canada**
  - 22: 97
  - 8728: 10
  - 8021: 6
  - 12361: 3
  - 12448: 2
- **Germany**
  - 22: 50
  - 5006: 8
  - 27777: 8
  - 2999: 4
  - 3601: 4
- **India**
  - 22: 261
  - 25: 2
- **United States**
  - 22: 322
  - 5902: 113
  - 1181: 78
  - 5903: 56
  - 5901: 54

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 6
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2016-20017 CVE-2025-14094 CVE-2025-14094 CVE-2016-20017: 1
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2021-35395 CVE-2021-35395: 1

**Usernames:**
- root: 182
- oracle: 85
- guest: 66
- user: 61
- postgres: 53
- test: 46
- mysql: 41
- admin: 40
- deploy: 28
- git: 19

**Passwords:**
- 123456: 77
- password: 40
- 123: 39
- 1234: 38
- 12345678: 37

**OS Distribution:**
- Linux 2.2.x-3.x: 15252
- Linux 2.2.x-3.x (barebone): 245
- Windows NT kernel 5.x: 192
- Linux 2.2.x-3.x (no timestamps): 154
- Windows NT kernel: 78


**Hyper-aggressive IPs:**
- 157.245.101.183: 705
- 165.227.118.67: 554
- 192.241.189.141: 515
- 138.197.136.0: 486
- 170.64.152.98: 425
