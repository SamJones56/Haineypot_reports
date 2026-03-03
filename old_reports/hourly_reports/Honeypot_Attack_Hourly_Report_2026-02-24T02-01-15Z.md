# Honeypot Attack Report - 2026-02-24T02:00:23Z

## Executive Summary:
- The honeypot network observed 2,228 attacks in the past hour.
- The majority of attacks originated from the United States (1,101), followed by Seychelles (281) and Romania (186).
- The most prominent attacker IP was 45.87.249.140 with 280 attacks.
- "Generic Protocol Command Decode" was the most common alert category, with "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet" being the top alert signatures.
- Attackers were observed attempting to exploit CVE-2006-2369.
- Common credential stuffing pairs included root/123456 and admin/123456.

## Detailed Analysis:

**Total Attacks:**
- 2228

**Top Attacking Countries:**
- United States: 1101
- Seychelles: 281
- Romania: 186
- Switzerland: 124
- Netherlands: 116

**Notable IP Reputations:**
- known attacker: 1329
- mass scanner: 139

**Common Alert Categories:**
- Generic Protocol Command Decode: 2193
- Misc activity: 543
- Misc Attack: 378
- Attempted Information Leak: 80
- Attempted Administrator Privilege Gain: 73

**Alert Signatures:**
- 2200003: SURICATA IPv4 truncated packet: 909
- 2200122: SURICATA AF-PACKET truncated packet: 909
- 2100560: GPL INFO VNC server response: 344
- 2228000: SURICATA SSH invalid banner: 187
- 2402000: ET DROP Dshield Block Listed Source group 1: 159

**ASN Information:**
- 14061: DigitalOcean, LLC: 388
- 47890: Unmanaged Ltd: 316
- 210006: Shereverov Marat Ahmedovich: 280
- 396982: Google LLC: 278
- 51852: Private Layer INC: 124

**Source IP Addresses:**
- 45.87.249.140: 280
- 46.19.137.194: 124
- 129.212.184.194: 112
- 2.57.122.208: 107
- 134.199.197.108: 57

**Country to Port Mapping:**
- Netherlands
  - 9100: 24
  - 6036: 12
  - 17000: 8
  - 22: 6
  - 4006: 2
- Romania
  - 22: 31
  - 16138: 2
  - 19631: 2
  - 22398: 2
  - 26475: 2
- Seychelles
  - 22: 56
  - 9042: 1
- Switzerland
  - 5435: 123
  - 5432: 1
- United States
  - 5902: 112
  - 1494: 78
  - 5903: 57
  - 5901: 53
  - 9100: 21

**CVEs Exploited:**
- CVE-2006-2369: 64
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2023-46604 CVE-2023-46604 CVE-2023-46604: 2
- CVE-2009-2765: 1
- CVE-2016-6563: 1

**Usernames:**
- root: 30
- admin: 19
- user: 11
- ubuntu: 7
- ubnt: 5
- sol: 3
- user1: 3
- ftp: 2
- guest: 2
- solana: 2

**Passwords:**
- 123456: 7
- ubuntu: 4
- 123: 3
- 1234: 3
- 12345: 3

**OS Distribution:**
- Linux 2.2.x-3.x: 13781
- Linux 3.1-3.10: 1367
- Linux 3.11 and newer: 1061
- Windows NT kernel: 2309
- Linux 3.x: 460

**Hyper-aggressive IPs:**
- 45.87.249.140: 280
