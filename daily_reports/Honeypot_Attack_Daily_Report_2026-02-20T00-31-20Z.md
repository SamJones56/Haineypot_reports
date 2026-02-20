# Honeypot Attack Report - 2026-02-20T00:30:13Z

## Executive Summary:
- **High Attack Volume:** A total of 51,266 attacks were observed in the last 24 hours.
- **Dominant Attacker:** Vietnam was the most active attacking country, responsible for over half of the total attacks. A single IP address, 103.237.145.16, from Vietnam, was responsible for 26,188 attacks, indicating a targeted campaign.
- **Common Attack Vectors:** The most common alert categories were "Generic Protocol Command Decode" and "Misc activity". The most frequent alert signature was "GPL INFO VNC server response".
- **Exploitation Attempts:** Several CVEs were targeted, with CVE-2024-14007 being the most frequently exploited.
- **Credential Stuffing:** Brute-force attempts were prevalent, with "root" being the most common username and "password" the most common password.
- **Attacker Infrastructure:** The majority of attacks originated from systems running Linux, with a significant number also coming from Windows-based systems.

## Detailed Analysis:

**Total Attacks:**
- 51,266

**Top Attacking Countries:**
- Vietnam: 26,252
- United States: 6,857
- Germany: 5,687
- Singapore: 3,503
- India: 2,000

**Notable IP Reputations:**
- known attacker: 34,921
- mass scanner: 1,161
- tor exit node: 6
- bot, crawler: 2

**Common Alert Categories:**
- Generic Protocol Command Decode: 19,718
- Misc activity: 15,703
- Misc Attack: 2,516
- Attempted Information Leak: 472
- Potentially Bad Traffic: 218
- Attempted Administrator Privilege Gain: 91
- Detection of a Network Scan: 29
- Web Application Attack: 23
- access to a potentially vulnerable web application: 20
- Unknown Traffic: 11

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 14,682
- 2200003 - SURICATA IPv4 truncated packet: 9,303
- 2200122 - SURICATA AF-PACKET truncated packet: 9,303
- 2402000 - ET DROP Dshield Block Listed Source group 1: 776
- 2001978 - ET INFO SSH session in progress on Expected Port: 470
- 2210048 - SURICATA STREAM reassembly sequence GAP -- missing packet(s): 347
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 345
- 2009582 - ET SCAN NMAP -sS window 1024: 260
- 2210051 - SURICATA STREAM Packet with broken ack: 174
- 2001984 - ET INFO SSH session in progress on Unusual Port: 110

**ASN Information:**
- 131414 - Long Van Soft Solution JSC: 26,188
- 14061 - DigitalOcean, LLC: 12,797
- 8075 - Microsoft Corporation: 2,618
- 396982 - Google LLC: 1,516
- 174 - Cogent Communications, LLC: 1,195
- 135377 - UCLOUD INFORMATION TECHNOLOGY HK LIMITED: 809
- 213412 - ONYPHE SAS: 743
- 202425 - IP Volume inc: 653
- 47890 - Unmanaged Ltd: 574
- 209334 - Modat B.V.: 473

**Source IP Addresses:**
- 103.237.145.16: 26,188
- 4.145.113.4: 2,441
- 139.59.82.171: 1,608
- 207.154.239.37: 1,503
- 207.154.211.38: 1,300
- 104.248.249.212: 1,275
- 165.227.161.214: 1,249
- 134.199.173.128: 970
- 134.199.153.94: 923
- 152.42.206.51: 520

**Country to Port Mapping:**
- **Australia**
  - 22: 375
  - 23: 1
- **Canada**
  - 8728: 24
  - 12269: 5
  - 9220: 4
  - 21078: 4
  - 1207: 3
  - 2222: 3
  - 2351: 3
  - 3200: 3
  - 7510: 3
  - 8024: 3
- **Germany**
  - 22: 1,071
  - 1723: 47
  - 50001: 16
  - 9443: 14
  - 20443: 14
  - 60443: 14
  - 445: 9
  - 7443: 8
  - 32810: 8
  - 3000: 7
- **India**
  - 22: 377
  - 8728: 35
  - 8085: 16
  - 30005: 14
  - 25: 6
  - 1224: 2
  - 8090: 2
  - 55555: 2
  - 2222: 1
  - 5985: 1
- **Netherlands**
  - 443: 191
  - 9100: 64
  - 80: 43
  - 17000: 32
  - 6037: 28
  - 8728: 28
  - 17001: 28
  - 6036: 24
  - 27017: 24
  - 22: 20
- **Romania**
  - 22: 116
- **Singapore**
  - 5910: 245
  - 5901: 244
  - 5902: 244
  - 5903: 244
  - 5904: 244
  - 5905: 244
  - 5906: 244
  - 5907: 244
  - 5908: 244
  - 5909: 244
- **United Kingdom**
  - 22: 35
  - 8088: 18
  - 30443: 14
  - 1241: 10
  - 8081: 8
  - 1248: 7
  - 9527: 7
  - 11479: 7
  - 23: 6
  - 80: 4
- **United States**
  - 22: 165
  - 8728: 64
  - 80: 53
  - 3399: 44
  - 27018: 38
  - 25: 36
  - 443: 36
  - 15671: 35
  - 27019: 35
  - 17000: 34
- **Vietnam**
  - 22: 5,244
  - 2379: 28
  - 8899: 7
  - 2222: 1

**CVEs Exploited:**
- CVE-2024-14007: 21
- CVE-2025-55182: 15
- CVE-2021-3449: 9
- CVE-2019-11500: 7
- CVE-2002-0013 CVE-2002-0012: 3
- CVE-2003-0825: 2
- CVE-2006-2369: 2
- CVE-2010-0569: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2

**Usernames:**
- root: 5,574
- admin: 153
- sa: 91
- backup: 84
- docker: 82
- oracle: 82
- mysql: 80
- guest: 79
- postgres: 78
- debian: 75

**Passwords:**
- password: 176
- 123456: 171
- qwerty: 131
- 12345: 126
- 12345678: 123
- 123456789: 123
- 1234567: 103
- welcome: 78
- letmein: 77
- 123123: 67

**OS Distribution:**
- Linux 2.2.x-3.x: 85,555
- Linux 2.2.x-3.x (barebone): 3,421
- Windows NT kernel 5.x: 59,814
- Linux 3.11 and newer: 315
- Linux 2.2.x-3.x (no timestamps): 375
- Mac OS X: 187
- Windows NT kernel: 2,917
- Windows 7 or 8: 16
- Linux 3.1-3.10: 23
- Linux 3.x: 13

**Hyper-aggressive IPs:**
- 103.237.145.16: 26,188 attacks
- 4.145.113.4: 2,441 attacks
- 139.59.82.171: 1,608 attacks
- 207.154.239.37: 1,503 attacks
- 134.199.173.128: 970 attacks
