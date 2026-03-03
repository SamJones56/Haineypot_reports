# Honeypot Attack Report - 2026-02-23T00:15:25Z

Executive Summary:
- **High Attack Volume:** A total of 43,520 attacks were observed in the last 6 hours.
- **Dominant Actors:** The majority of attacks originated from Australia and the United States, with DigitalOcean (AS14061) being the most prominent ASN.
- **Top Attacker:** The IP address 209.38.80.88 was the most aggressive, with 4,000 attacks.
- **Common Tactics:** The most frequent alert category was "Generic Protocol Command Decode", and the most common alert signature was "SURICATA IPv4 truncated packet".
- **Credential Stuffing:** "root" and "admin" were the most common usernames, while "123456" and "password" were the most common passwords.
- **Exploitation:** CVE-2024-14007 was the most exploited vulnerability.

Detailed Analysis:

Total Attacks:
- 43520

Top Attacking Countries:
- Australia: 11415
- United States: 10206
- United Kingdom: 5309
- Germany: 3282
- India: 2028

Notable IP Reputations:
- known attacker: 10052
- mass scanner: 496
- bot, crawler: 15

Common Alert Categories:
- Generic Protocol Command Decode: 10387
- Misc activity: 3185
- Misc Attack: 1443
- Attempted Information Leak: 531
- Attempted Administrator Privilege Gain: 134
- Potentially Bad Traffic: 89
- Web Application Attack: 86
- A Network Trojan was detected: 42
- access to a potentially vulnerable web application: 22
- Detection of a Network Scan: 18

Alert Signatures:
- 2200003 - SURICATA IPv4 truncated packet: 4229
- 2200122 - SURICATA AF-PACKET truncated packet: 4229
- 2100560 - GPL INFO VNC server response: 1354
- 2228000 - SURICATA SSH invalid banner: 1067
- 2001978 - ET INFO SSH session in progress on Expected Port: 803
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 493
- 2001984 - ET INFO SSH session in progress on Unusual Port: 491
- 2402000 - ET DROP Dshield Block Listed Source group 1: 397
- 2009582 - ET SCAN NMAP -sS window 1024: 269
- 2023753 - ET SCAN MS Terminal Server Traffic on Non-standard Port: 189

ASN Information:
- 14061, DigitalOcean, LLC: 28157
- 210006, Shereverov Marat Ahmedovich: 2054
- 47890, Unmanaged Ltd: 1907
- 202425, IP Volume inc: 1270
- 37693, TUNISIANA: 1176
- 8781, Ooredoo Q.S.C.: 1142
- 131427, AOHOAVIET: 958
- 396982, Google LLC: 889
- 51852, Private Layer INC: 515
- 27699, TELEFONICA BRASIL S.A: 513

Source IP Addresses:
- 209.38.80.88: 4000
- 209.38.29.178: 3587
- 170.64.162.36: 2593
- 178.20.210.32: 2054
- 167.172.56.108: 1434
- 161.35.39.52: 1358
- 165.245.191.137: 1254
- 197.14.55.168: 1176
- 178.153.127.226: 1142
- 159.89.162.36: 1097

Country to Port Mapping:
- Australia
  - 22: 2267
- Germany
  - 22: 591
  - 23: 15
  - 6443: 15
  - 445: 14
  - 1026: 9
- India
  - 22: 397
  - 23: 2
  - 25: 2
  - 2222: 2
  - 8188: 1
- United Kingdom
  - 22: 1013
  - 80: 16
  - 1026: 9
  - 443: 7
  - 10443: 4
- United States
  - 22: 809
  - 5902: 698
  - 1025: 380
  - 5903: 345
  - 5901: 326

CVEs Exploited:
- CVE-2024-14007 CVE-2024-14007: 32
- CVE-2025-55182 CVE-2025-55182: 21
- CVE-2021-3449 CVE-2021-3449: 9
- CVE-2002-0953: 8
- CVE-2019-11500 CVE-2019-11500: 8
- CVE-2002-0013 CVE-2002-0012: 3
- CVE-2006-2369: 2
- CVE-2023-46604 CVE-2023-46604 CVE-2023-46604: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2

Usernames:
- root: 1007
- admin: 547
- user: 282
- postgres: 222
- test: 217
- git: 209
- oracle: 182
- ubuntu: 132
- hadoop: 130
- mysql: 104

Passwords:
- 123456: 796
- 123: 216
- password: 209
- 1234: 163
- 12345678: 155
- 12345: 135
- qwerty: 124
- 123456789: 119
- passw0rd: 104
- admin: 103

OS Distribution:
- Linux 2.2.x-3.x: 85621
- Windows NT kernel: 14200
- Linux 2.2.x-3.x (no timestamps): 2192
- Linux 2.2.x-3.x (barebone): 1864
- Windows 7 or 8: 1667
- Windows NT kernel 5.x: 610
- Linux 3.11 and newer: 217
- Mac OS X: 85
- Linux 3.1-3.10: 48
- Linux 2.4.x-2.6.x: 5

Hyper-aggressive IPs:
- 209.38.80.88: 4000
- 209.38.29.178: 3587
- 170.64.162.36: 2593
- 178.20.210.32: 2054
