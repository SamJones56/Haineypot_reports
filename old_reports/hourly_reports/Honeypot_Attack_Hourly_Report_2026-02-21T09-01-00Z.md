# Honeypot Attack Report - 2026-02-21T09:00:18Z

Executive Summary:
- Over the past hour, a total of 4,685 attacks were detected.
- The majority of attacks originated from China (2,582), followed by the United States (806).
- A single IP address, 218.21.0.230, was responsible for 2,509 attacks, indicating a highly aggressive source.
- The most common alert category was "Generic Protocol Command Decode," with 4,615 instances.
- The most frequent alert signatures were "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet," each with 2,060 occurrences.
- The dominant attacking operating system was identified as Linux.

Detailed Analysis:

Total Attacks:
- 4685

Top Attacking Countries:
- China: 2582
- United States: 806
- Netherlands: 239
- Romania: 239
- Canada: 192

Notable IP Reputations:
- known attacker: 1588
- mass scanner: 141

Common Alert Categories:
- Generic Protocol Command Decode: 4615
- Misc activity: 450
- Misc Attack: 424
- Attempted Information Leak: 88
- Potentially Bad Traffic: 38

Alert Signatures:
- 2200003 - SURICATA IPv4 truncated packet: 2060
- 2200122 - SURICATA AF-PACKET truncated packet: 2060
- 2100560 - GPL INFO VNC server response: 230
- 2228000 - SURICATA SSH invalid banner: 215
- 2402000 - ET DROP Dshield Block Listed Source group 1: 136

ASN Information:
- 4134 - Chinanet: 2526
- 47890 - Unmanaged Ltd: 363
- 396982 - Google LLC: 288
- 209334 - Modat B.V.: 185
- 51852 - Private Layer INC: 156

Source IP Addresses:
- 218.21.0.230: 2509
- 46.19.137.194: 156
- 2.57.122.208: 108
- 34.158.168.101: 97
- 2.57.122.238: 80

Country to Port Mapping:
- Canada
  - 8728: 6
  - 1400: 3
  - 9592: 3
  - 1226: 2
  - 1553: 2
- China
  - 22: 498
  - 1433: 15
  - 23: 11
  - 5005: 6
  - 6379: 6
- Netherlands
  - 443: 95
  - 1337: 40
  - 80: 15
  - 22: 9
  - 6036: 8
- Romania
  - 22: 37
  - 2121: 2
  - 3395: 2
  - 3401: 2
  - 3408: 2
- United States
  - 27018: 35
  - 29092: 35
  - 8728: 13
  - 61002: 13
  - 61007: 13

CVEs Exploited:
- CVE-2024-14007 CVE-2024-14007: 6
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2018-2893 CVE-2018-2893 CVE-2018-2893: 2
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2025-55182 CVE-2025-55182: 1

Usernames:
- root: 523
- sa: 15
- sol: 9
- solv: 6
- ubuntu: 6
- postgres: 4
- GET / HTTP/1.1: 2
- node: 2
- solana: 2
- trader: 2

Passwords:
- password: 8
- 123456: 7
- 123: 4
- 1234: 4
- 12345678: 4

OS Distribution:
- Linux 2.2.x-3.x: 13074
- Windows NT kernel: 12130
- Linux 2.2.x-3.x (barebone): 314
- Windows NT kernel 5.x: 187
- Linux 2.2.x-3.x (no timestamps): 115

Hyper-aggressive IPs:
- 218.21.0.230: 2509
