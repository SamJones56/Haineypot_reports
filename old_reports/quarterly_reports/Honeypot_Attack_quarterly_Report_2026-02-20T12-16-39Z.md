# Honeypot Attack Report - 2026-02-20T12:15:36Z

### Executive Summary:
- Over 32,000 attacks were recorded in the past 6 hours, with a significant number originating from Germany and the United States.
- Two IP addresses, 213.154.18.82 (Aztelekom LLC, Azerbaijan) and 182.10.97.25 (PT. Telekomunikasi Selular, Indonesia), were identified as hyper-aggressive, accounting for a substantial portion of the attack volume.
- The majority of attacks were categorized as "Misc activity" and "Generic Protocol Command Decode".
- The most frequent alert signature was "GPL INFO VNC server response", indicating widespread VNC server scanning.
- Brute-force attempts commonly used default credentials such as 'root' and 'admin' for usernames and '123456' and 'password' for passwords.
- The dominant operating systems of attacking machines were identified as Linux 2.2.x-3.x and Windows NT kernel.

### Detailed Analysis:

**Total Attacks:**
- 32816

**Top Attacking Countries:**
- Germany: 5038
- United States: 5033
- Indonesia: 3123
- Azerbaijan: 3108
- India: 2446

**Notable IP Reputations:**
- known attacker: 7146
- mass scanner: 1400
- bot, crawler: 10

**Common Alert Categories:**
- Misc activity: 14678
- Generic Protocol Command Decode: 12456
- Misc Attack: 2487
- Attempted Administrator Privilege Gain: 1546
- Attempted Information Leak: 614
- Potentially Bad Traffic: 149
- Detection of a Network Scan: 31
- Not Suspicious Traffic: 16
- Web Application Attack: 11
- Detection of a Denial of Service Attack: 9

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 13678
- 2200003 - SURICATA IPv4 truncated packet: 4964
- 2200122 - SURICATA AF-PACKET truncated packet: 4964
- 2024766 - ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1384
- 2221010 - SURICATA HTTP unable to match response to request: 685
- 2402000 - ET DROP Dshield Block Listed Source group 1: 669
- 2001978 - ET INFO SSH session in progress on Expected Port: 424
- 2210051 - SURICATA STREAM Packet with broken ack: 376
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 366
- 2023753 - ET SCAN MS Terminal Server Traffic on Non-standard Port: 293

**ASN Information:**
- 14061 - DigitalOcean, LLC: 9792
- 28787 - Aztelekom LLC: 3108
- 23693 - PT. Telekomunikasi Selular: 3101
- 8075 - Microsoft Corporation: 1956
- 138277 - Radinet Info Solutions Private Limited: 1733
- 27699 - TELEFONICA BRASIL S.A: 1348
- 396982 - Google LLC: 1232
- 701 - Verizon Business: 796
- 209334 - Modat B.V.: 721
- 213412 - ONYPHE SAS: 718

**Source IP Addresses:**
- 213.154.18.82: 3108
- 182.10.97.25: 3101
- 4.145.113.4: 1795
- 103.133.122.38: 1733
- 206.189.61.203: 1536
- 144.126.205.38: 1505
- 167.99.218.227: 1476
- 201.1.161.225: 1348
- 206.81.21.204: 1248
- 164.90.185.60: 901

**Country to Port Mapping:**
- Azerbaijan:
  - 445: 3108
- Brazil:
  - 445: 1348
  - 9487: 7
  - 9496: 7
  - 23: 4
  - 80: 2
- Germany:
  - 22: 941
  - 9000: 11
  - 80: 8
  - 3306: 8
  - 4032: 8
- India:
  - 445: 1738
  - 23: 135
  - 22: 84
- Indonesia:
  - 445: 3101
  - 9481: 7
  - 27914: 7
  - 23: 3
  - 1433: 1
- Netherlands:
  - 22: 322
  - 443: 191
  - 80: 50
  - 6037: 24
  - 27017: 23
- Russia:
  - 445: 531
  - 28017: 37
  - 1521: 24
  - 4369: 22
  - 5986: 14
- Singapore:
  - 5901: 180
  - 5902: 180
  - 5903: 180
  - 5905: 180
  - 5908: 180
- United Kingdom:
  - 22: 293
  - 9000: 13
  - 8090: 10
  - 3306: 8
  - 5400: 7
- United States:
  - 445: 812
  - 6379: 73
  - 25: 70
  - 8728: 66
  - 80: 50

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 14
- CVE-2021-3449 CVE-2021-3449: 9
- CVE-2019-11500 CVE-2019-11500: 7
- CVE-2025-55182 CVE-2025-55182: 7
- CVE-2020-2551 CVE-2020-2551 CVE-2020-2551: 4
- CVE-2002-0606: 2
- CVE-2023-26801 CVE-2023-26801: 2
- CVE-2006-2369: 1
- CVE-2020-14882 CVE-2020-14883 CVE-2020-14882: 1

**Usernames:**
- root: 543
- admin: 166
- ubuntu: 107
- oracle: 89
- postgres: 87
- debian: 79
- test: 76
- user: 76
- guest: 60
- backup: 50

**Passwords:**
- : 152
- 123456: 120
- password: 117
- 12345: 95
- 123456789: 92
- welcome: 74
- admin: 68
- password1: 61
- 1234: 56
- admin123: 55

**OS Distribution:**
- Linux 2.2.x-3.x: 91118
- Windows NT kernel: 102709
- Linux 2.2.x-3.x (barebone): 1955
- Windows NT kernel 5.x: 58106
- Linux 2.2.x-3.x (no timestamps): 622
- Linux 3.11 and newer: 243
- Mac OS X: 220
- Linux 3.1-3.10: 58
- Windows 7 or 8: 10700
- FreeBSD: 14

**Hyper-aggressive IPs:**
- 213.154.18.82: 3108
- 182.10.97.25: 3101
