# Honeypot Attack Report - 2026-02-22T17:00:19Z

## Executive Summary:
- Over 5,000 attacks were observed in the past hour, with the United States, United Kingdom, and Germany being the most active attacking countries.
- The majority of attacks originated from ASN 14061 (DigitalOcean, LLC).
- A significant portion of attacking IPs, nearly 2,000, are already flagged as known attackers.
- The most common alert category was "Generic Protocol Command Decode", indicating a high volume of reconnaissance and protocol-level probing.
- The top alert signature was related to truncated packets, suggesting either network issues or deliberate attempts to evade detection.
- Brute-force activity remains prevalent, with "root" and "admin" as the most frequently used usernames.

## Detailed Analysis:

**Total Attacks:**
- 5090

**Top Attacking Countries:**
- United States: 1076
- United Kingdom: 912
- Germany: 857
- Netherlands: 620
- Romania: 336

**Notable IP Reputations:**
- known attacker: 1991
- mass scanner: 64

**Common Alert Categories:**
- Generic Protocol Command Decode: 1303
- Misc activity: 509
- Attempted Administrator Privilege Gain: 251
- Misc Attack: 219
- Attempted Information Leak: 64

**Alert Signatures:**
- 2200003 - SURICATA IPv4 truncated packet: 492
- 2200122 - SURICATA AF-PACKET truncated packet: 492
- 2024766 - ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 246
- 2100560 - GPL INFO VNC server response: 226
- 2228000 - SURICATA SSH invalid banner: 176

**ASN Information:**
- 14061 - DigitalOcean, LLC: 2354
- 47890 - Unmanaged Ltd: 439
- 210006 - Shereverov Marat Ahmedovich: 330
- 202425 - IP Volume inc: 251
- 20473 - The Constant Company, LLC: 233

**Source IP Addresses:**
- 146.190.25.148: 512
- 104.248.136.117: 451
- 178.20.210.32: 330
- 178.62.41.116: 326
- 138.68.135.71: 258

**Country to Port Mapping:**
- Germany:
  - 22: 157
  - 23: 17
  - 445: 13
  - 8089: 4
  - 10199: 4
- Netherlands:
  - 22: 109
  - 6036: 16
  - 23: 10
  - 17000: 8
  - 25: 7
- Romania:
  - 22: 56
  - 8281: 2
  - 8494: 2
  - 8956: 2
  - 12166: 2
- United Kingdom:
  - 22: 157
  - 4444: 4
  - 80: 3
  - 27017: 3
  - 1102: 2
- United States:
  - 5902: 113
  - 31337: 78
  - 5903: 56
  - 5901: 54
  - 27018: 35

**CVEs Exploited:**
- CVE-2025-55182
- CVE-2024-14007
- CVE-2002-0013
- CVE-2002-0012
- CVE-2019-11500
- CVE-2021-3449

**Usernames:**
- root: 139
- admin: 78
- user: 46
- test: 40
- postgres: 33
- oracle: 31
- dspace: 21
- debian: 16
- dev: 12
- odoo: 12

**Passwords:**
- 123456: 25
- 123: 17
- 654321: 17
- 12345678: 16
- 123qwe: 16

**OS Distribution:**
- Linux 2.2.x-3.x: 18515
- Windows NT kernel: 9500
- Linux 2.2.x-3.x (barebone): 285
- Linux 2.2.x-3.x (no timestamps): 416
- Windows NT kernel 5.x: 84

**Hyper-aggressive IPs:**
- 146.190.25.148: 512 attacks
- 104.248.136.117: 451 attacks
- 178.20.210.32: 330 attacks
- 178.62.41.116: 326 attacks
- 138.68.135.71: 258 attacks
