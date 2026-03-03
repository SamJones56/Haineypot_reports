# Honeypot Attack Report - 2026-02-24T07:00:19Z

Executive Summary:
- Over 2,400 attacks were observed in the past hour, with the United States being the most dominant source country, accounting for nearly half of all attacks.
- The majority of attackers are identified as "known attackers," indicating a high level of repeated malicious activity from these sources.
- The most common attack category is "Generic Protocol Command Decode," suggesting a focus on reconnaissance and service enumeration.
- Several hyper-aggressive IPs were identified, with three IPs accounting for over 650 attacks combined.
- The most common operating system identified for attackers is Linux 2.2.x-3.x.
- Common usernames and passwords like "test," "admin," "123456," and "password" continue to be popular targets for brute-force attacks.

Detailed Analysis:

Total Attacks:
- 2403

Top Attacking Countries:
- United States: 1134
- Switzerland: 321
- Vietnam: 227
- Netherlands: 164
- United Kingdom: 112

Notable IP Reputations:
- known attacker: 1554
- mass scanner: 184
- bot, crawler: 2

Common Alert Categories:
- Generic Protocol Command Decode: 802
- Misc activity: 394
- Misc Attack: 377
- Attempted Information Leak: 94
- Potentially Bad Traffic: 21

Alert Signatures:
- 2200003: SURICATA IPv4 truncated packet: 227
- 2200122: SURICATA AF-PACKET truncated packet: 227
- 2228000: SURICATA SSH invalid banner: 221
- 2100560: GPL INFO VNC server response: 216
- 2402000: ET DROP Dshield Block Listed Source group 1: 121

ASN Information:
- 14061: DigitalOcean, LLC: 424
- 51852: Private Layer INC: 321
- 396982: Google LLC: 268
- 131427: AOHOAVIET: 227
- 47890: Unmanaged Ltd: 203

Source IP Addresses:
- 46.19.137.194: 321
- 103.53.231.159: 227
- 129.212.184.194: 112
- 34.158.168.101: 99
- 134.199.197.108: 57

Country to Port Mapping:
- Netherlands
  - 443: 98
  - 6036: 8
  - 6037: 8
  - 9100: 8
  - 17000: 8
- Switzerland
  - 25432: 320
  - 5432: 1
- United Kingdom
  - 22: 11
  - 80: 5
  - 631: 2
  - 3893: 2
  - 4000: 2
- United States
  - 1813: 117
  - 5902: 112
  - 5903: 57
  - 5901: 56
  - 445: 35
- Vietnam
  - 22: 45

CVEs Exploited:
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2025-55182 CVE-2025-55182: 2
- CVE-2002-0013 CVE-2002-0012: 1
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2021-3449 CVE-2021-3449: 1

Usernames:
- test: 46
- admin: 18
- user: 10
- root: 7
- dev: 4
- sql: 4
- database: 3
- steam: 2
- postgres: 1

Passwords:
- admin: 4
- 123456: 3
- 12345678: 3
- password: 3
- 0000: 2

OS Distribution:
- Linux 2.2.x-3.x: 13046
- Linux 2.2.x-3.x (barebone): 352
- Windows NT kernel 5.x: 150
- Windows NT kernel: 65
- Linux 2.2.x-3.x (no timestamps): 187

Hyper-aggressive IPs:
- 46.19.137.194: 321
- 103.53.231.159: 227
- 129.212.184.194: 112
