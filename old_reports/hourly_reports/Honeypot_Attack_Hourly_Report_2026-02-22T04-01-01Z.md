# Honeypot Attack Report - 2026-02-22T04:00:19Z

## Executive Summary:
- Over 4,200 attacks were observed in the past hour, with the majority originating from the United States.
- The most prominent attacker IP, 144.202.31.88, is associated with The Constant Company, LLC.
- A significant portion of attackers are labeled as "known attackers".
- The most frequent alert signature is "SURICATA SSH invalid banner".
- Brute-force attempts are common, with "git" and "hadoop" as the most used usernames and "123456" as the most common password.
- The primary attacking OS is Linux.

## Detailed Analysis:

**Total Attacks:**
- 4288

**Top Attacking Countries:**
- United States: 1846
- India: 715
- Australia: 451
- Germany: 350
- Romania: 297

**Notable IP Reputations:**
- known attacker: 1658
- mass scanner: 122
- bot, crawler: 2

**Common Alert Categories:**
- Generic Protocol Command Decode: 695
- Misc activity: 477
- Misc Attack: 355
- Attempted Information Leak: 96
- Potentially Bad Traffic: 25

**Alert Signatures:**
- 2228000 - SURICATA SSH invalid banner: 233
- 2100560 - GPL INFO VNC server response: 222
- 2200003 - SURICATA IPv4 truncated packet: 157
- 2200122 - SURICATA AF-PACKET truncated packet: 157
- 2001984 - ET INFO SSH session in progress on Unusual Port: 112

**ASN Information:**
- 14061 - DigitalOcean, LLC: 1241
- 20473 - The Constant Company, LLC: 629
- 47890 - Unmanaged Ltd: 408
- 9498 - BHARTI Airtel Ltd.: 370
- 210006 - Shereverov Marat Ahmedovich: 295

**Source IP Addresses:**
- 144.202.31.88: 629
- 59.145.41.149: 370
- 167.71.232.38: 340
- 209.38.23.244: 300
- 178.20.210.32: 295

**Country to Port Mapping:**
- Australia
  - 80: 117
  - 22: 68
- Germany
  - 22: 59
  - 8099: 4
  - 60510: 4
  - 61308: 4
  - 8135: 3
- India
  - 445: 370
  - 22: 68
  - 12000: 2
  - 2376: 1
  - 4243: 1
- Romania
  - 22: 53
  - 443: 3
  - 10554: 2
  - 14859: 2
  - 21385: 2
- United States
  - 2323: 356
  - 3388: 171
  - 23: 137
  - 5902: 115
  - 5903: 58

**CVEs Exploited:**
- CVE-2024-14007 
- CVE-2021-3449
- CVE-2023-46604
- CVE-2019-11500
- CVE-2025-55182

**Usernames:**
- git: 43
- hadoop: 23
- root: 20
- admin: 16
- test1: 13
- www: 12
- test2: 11
- test3: 11
- mysql: 10
- user: 10

**Passwords:**
- 123456: 12
- 1234: 9
- 123: 8
- 123qwe: 7
- 654321: 7

**OS Distribution:**
- Linux 2.2.x-3.x: 6041
- Windows NT kernel: 5459
- Linux 2.2.x-3.x (barebone): 288
- Windows NT kernel 5.x: 150
- Linux 2.2.x-3.x (no timestamps): 253

**Hyper-aggressive IPs:**
- 144.202.31.88: 629
- 59.145.41.149: 370
- 167.71.232.38: 340
- 209.38.23.244: 300
- 178.20.210.32: 295
