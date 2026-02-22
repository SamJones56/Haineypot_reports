# Honeypot Attack Report - 2026-02-22T12:15:38Z

## Executive Summary:
- Over the past 6 hours, the honeypot network observed 23,050 attacks, with the majority originating from the United States (8,374) and India (5,324).
- A significant portion of attacks (9,443) are attributed to ASN 14061 (DigitalOcean, LLC), with IP 139.59.62.156 from this ASN being the most aggressive, accounting for 3,307 attacks.
- The most common alert category was "Generic Protocol Command Decode" (3,314), and the top alert signature was "SURICATA SSH invalid banner" (1,433), indicating a high volume of SSH-related activity.
- Brute-force attempts are prevalent, with "root" (399) and "admin" (183) being the most targeted usernames, and "123456" (188) the most common password.
- The dominant attacking operating system appears to be Linux, with "Linux 2.2.x-3.x" accounting for 69,116 observed fingerprints.
- Several CVEs were detected, with CVE-2025-55182 being the most frequent.

## Detailed Analysis:

**Total Attacks:**
- 23,050

**Top Attacking Countries:**
- United States: 8,374
- India: 5,324
- Germany: 1,669
- Romania: 1,475
- Netherlands: 1,110

**Notable IP Reputations:**
- known attacker: 8,696
- mass scanner: 845
- bot, crawler: 6
- tor exit node: 1

**Common Alert Categories:**
- Generic Protocol Command Decode: 3,314
- Misc activity: 2,913
- Misc Attack: 2,092
- Attempted Information Leak: 677
- Potentially Bad Traffic: 126
- Attempted Administrator Privilege Gain: 66
- Web Application Attack: 25
- Detection of a Network Scan: 21
- access to a potentially vulnerable web application: 11
- Not Suspicious Traffic: 7

**Alert Signatures:**
- 2228000, SURICATA SSH invalid banner: 1,433
- 2100560, GPL INFO VNC server response: 1,362
- 2001984, ET INFO SSH session in progress on Unusual Port: 681
- 2402000, ET DROP Dshield Block Listed Source group 1: 578
- 2200003, SURICATA IPv4 truncated packet: 511
- 2200122, SURICATA AF-PACKET truncated packet: 511
- 2001978, ET INFO SSH session in progress on Expected Port: 429
- 2038967, ET INFO SSH-2.0-Go version string Observed in Network Traffic: 336
- 2023753, ET SCAN MS Terminal Server Traffic on Non-standard Port: 290
- 2009582, ET SCAN NMAP -sS window 1024: 265

**ASN Information:**
- 14061, DigitalOcean, LLC: 9,443
- 47890, Unmanaged Ltd: 2,196
- 396982, Google LLC: 1,587
- 9498, BHARTI Airtel Ltd.: 1,480
- 16509, Amazon.com, Inc.: 1,081
- 20473, The Constant Company, LLC: 942
- 209334, Modat B.V.: 531
- 204428, SS-Net: 377
- 202425, IP Volume inc: 334
- 398324, Censys, Inc.: 315

**Source IP Addresses:**
- 139.59.62.156: 3,307
- 59.145.41.149: 1,480
- 165.22.2.4: 1,174
- 129.212.184.194: 679
- 209.38.28.196: 671
- 165.22.26.70: 668
- 46.101.214.86: 479
- 159.65.92.74: 444
- 34.158.168.101: 388
- 143.110.179.223: 380

**Country to Port Mapping:**
- Australia
  - 22: 148
- Canada
  - 23: 16
  - 8728: 12
  - 8880: 5
  - 1125: 4
  - 1529: 4
- Germany
  - 22: 261
  - 8000: 24
  - 80: 18
  - 4000: 10
  - 443: 8
- India
  - 445: 1480
  - 22: 740
  - 23: 51
  - 443: 2
- Japan
  - 23: 86
  - 8085: 12
  - 4460: 3
  - 8415: 3
  - 9202: 3
- Netherlands
  - 443: 384
  - 22: 83
  - 1337: 40
  - 9100: 29
  - 23: 27
- Romania
  - 22: 208
  - 33333: 20
  - 33389: 18
  - 11111: 16
  - 33895: 16
- Switzerland
  - 54322: 90
  - 6543: 80
  - 5435: 46
  - 5432: 18
- United Kingdom
  - 22: 83
  - 80: 13
  - 443: 9
  - 25: 7
  - 3306: 6
- United States
  - 5902: 685
  - 5903: 342
  - 5901: 341
  - 22: 292
  - 23: 124

**CVEs Exploited:**
- CVE-2025-55182 CVE-2025-55182: 11
- CVE-2024-14007 CVE-2024-14007: 10
- CVE-2021-3449 CVE-2021-3449: 6
- CVE-2023-46604 CVE-2023-46604 CVE-2023-46604: 6
- CVE-2019-11500 CVE-2019-11500: 4

**Usernames:**
- root: 399
- admin: 183
- user: 104
- ubuntu: 90
- test: 71
- guest: 58
- postgres: 48
- oracle: 46
- ftptest: 29
- elastic: 27

**Passwords:**
- 123456: 188
- password: 73
- 123: 53
- 1234: 52
- 12345: 51
- 12345678: 45
- admin: 42
- : 40
- 123456789: 36
- passw0rd: 34

**OS Distribution:**
- Linux 2.2.x-3.x: 69,116
- Windows NT kernel: 13,601
- Linux 2.2.x-3.x (barebone): 2,011
- Windows 7 or 8: 1,613
- Linux 2.2.x-3.x (no timestamps): 1,006
- Windows NT kernel 5.x: 926
- Linux 3.11 and newer: 244
- Mac OS X: 97
- Linux 3.1-3.10: 63
- Linux 3.x: 10

**Hyper-aggressive IPs:**
- 139.59.62.156: 3,307
- 59.145.41.149: 1,480
- 165.22.2.4: 1,174
