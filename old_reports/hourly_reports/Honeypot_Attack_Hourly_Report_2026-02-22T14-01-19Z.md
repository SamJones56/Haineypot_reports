# Honeypot Attack Report - 2026-02-22T14:00:16Z

**Executive Summary:**
- Over 3,600 attacks were observed in the past hour, with the United States, Germany, and the United Kingdom being the primary sources.
- The most prominent attacker IP, 45.10.175.246, was responsible for over 600 attacks and is associated with Cloudie Limited (ASN 55933).
- A significant portion of attacks (1,631) originated from IPs with a "known attacker" reputation.
- The most frequent alert signature was "GPL INFO VNC server response", indicating VNC server reconnaissance.
- Brute force activity remains prevalent, with "root" and "admin" being the most common usernames and "123456" the most common password.
- The overwhelming majority of attacking systems were identified as running Linux.

**Detailed Analysis:**

**Total Attacks:**
- 3606

**Top Attacking Countries:**
- United States: 1060
- Germany: 776
- United Kingdom: 746
- Romania: 386
- Switzerland: 183

**Notable IP Reputations:**
- known attacker: 1631
- mass scanner: 100
- bot, crawler: 2

**Common Alert Categories:**
- Generic Protocol Command Decode: 550
- Misc activity: 464
- Misc Attack: 322
- Attempted Information Leak: 143
- Successful Administrator Privilege Gain: 41

**Alert Signatures:**
- 2100560 (GPL INFO VNC server response): 228
- 2228000 (SURICATA SSH invalid banner): 196
- 2402000 (ET DROP Dshield Block Listed Source group 1): 113
- 2001984 (ET INFO SSH session in progress on Unusual Port): 93
- 2001978 (ET INFO SSH session in progress on Expected Port): 92

**ASN Information:**
- 14061 (DigitalOcean, LLC): 766
- 55933 (Cloudie Limited): 610
- 47890 (Unmanaged Ltd): 384
- 210006 (Shereverov Marat Ahmedovich): 340
- 396982 (Google LLC): 301

**Source IP Addresses:**
- 45.10.175.246: 610
- 46.101.191.46: 377
- 178.20.210.32: 340
- 46.19.137.194: 183
- 129.212.184.194: 113

**Country to Port Mapping:**
- Germany
  - 22: 137
  - 1433: 5
  - 8009: 4
  - 8803: 4
  - 9021: 4
- Romania
  - 22: 47
  - 22222: 10
  - 33389: 10
  - 33896: 10
  - 55555: 10
- Switzerland
  - 5433: 135
  - 5434: 46
  - 5432: 2
- United Kingdom
  - 22: 121
  - 80: 5
  - 53389: 4
  - 1102: 2
  - 1180: 2
- United States
  - 5902: 114
  - 4444: 59
  - 5984: 58
  - 5903: 56
  - 5901: 54

**CVEs Exploited:**
- CVE-2021-3449 CVE-2021-3449
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2023-26801 CVE-2023-26801
- CVE-2025-55182 CVE-2025-55182

**Usernames:**
- root: 77
- admin: 29
- mysql: 24
- postgres: 20
- user: 13
- ubuntu: 11
- daemon: 9
- solana: 9
- nexus: 6
- test: 5

**Passwords:**
- 123456: 33
- 123: 11
- password: 11
- 1234: 10
- 12345678: 10

**OS Distribution:**
- Linux 2.2.x-3.x: 11297
- Windows NT kernel: 7448
- Linux 2.2.x-3.x (barebone): 442
- Linux 2.2.x-3.x (no timestamps): 249
- Windows NT kernel 5.x: 120

**Hyper-aggressive IPs:**
- 45.10.175.246: 610
- 46.101.191.46: 377
- 178.20.210.32: 340
