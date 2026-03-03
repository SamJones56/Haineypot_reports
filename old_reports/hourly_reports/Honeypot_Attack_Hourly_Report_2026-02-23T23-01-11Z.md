# Honeypot Attack Report - 2026-02-23T23:00:29Z

## Executive Summary:
- Over the past hour, a total of 2,814 attacks were observed.
- The majority of attacks originated from the United States (1,192), followed by Seychelles (338) and Canada (316).
- A significant portion of the source IPs (1,862) were identified with a "known attacker" reputation.
- The most common alert category was "Generic Protocol Command Decode" with 611 instances.
- The alert signature "GPL INFO VNC server response" was triggered most frequently with 216 occurrences.
- The IP address 45.87.249.140, associated with AS210006 (Shereverov Marat Ahmedovich), was the most aggressive, accounting for 335 attacks.

## Detailed Analysis:

**Total Attacks:**
- 2,814

**Top Attacking Countries:**
- United States: 1192
- Seychelles: 338
- Canada: 316
- Switzerland: 231
- Vietnam: 176

**Notable IP Reputations:**
- known attacker: 1862
- mass scanner: 95
- bot, crawler: 1

**Common Alert Categories:**
- Generic Protocol Command Decode: 611
- Misc activity: 389
- Misc Attack: 322
- Attempted Information Leak: 97
- Potentially Bad Traffic: 21

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 216
- 2228000 - SURICATA SSH invalid banner: 170
- 2200003 - SURICATA IPv4 truncated packet: 141
- 2200122 - SURICATA AF-PACKET truncated packet: 141
- 2001984 - ET INFO SSH session in progress on Unusual Port: 85

**ASN Information:**
- 210006, Shereverov Marat Ahmedovich: 335
- 14061, DigitalOcean, LLC: 326
- 209334, Modat B.V.: 313
- 47890, Unmanaged Ltd: 233
- 51852, Private Layer INC: 231

**Source IP Addresses:**
- 45.87.249.140: 335
- 46.19.137.194: 231
- 103.53.231.159: 165
- 3.138.190.72: 122
- 129.212.184.194: 113

**Country to Port Mapping:**
- Canada
  - 8128: 3
  - 1128: 2
  - 1422: 2
  - 1998: 2
  - 2066: 2
- Seychelles
  - 22: 67
  - 23: 1
- Switzerland
  - 5434: 193
  - 5435: 36
  - 5432: 2
- United States
  - 5902: 123
  - 1453: 117
  - 5903: 58
  - 5901: 55
  - 6379: 15
- Vietnam
  - 22: 33
  - 3333: 11

**CVEs Exploited:**
- CVE-2024-14007
- CVE-2021-3449
- CVE-2025-55182
- CVE-2002-0013
- CVE-2002-0012
- CVE-2019-11500

**Usernames:**
- admin: 27
- root: 23
- user: 12
- remota: 8
- server: 8
- server1: 8
- solana: 8
- master1: 6
- postgres: 4
- remote1: 3

**Passwords:**
- 123: 12
- 123456: 11
- 1234: 10
- 12345678: 10
- admin: 6

**OS Distribution:**
- Linux 2.2.x-3.x: 9781
- Windows NT kernel: 21113
- Linux 2.2.x-3.x (barebone): 378
- Windows NT kernel 5.x: 163
- Linux 3.11 and newer: 46

**Hyper-aggressive IPs:**
- 45.87.249.140: 335
- 46.19.137.194: 231
- 103.53.231.159: 165
- 3.138.190.72: 122
- 129.212.184.194: 113
