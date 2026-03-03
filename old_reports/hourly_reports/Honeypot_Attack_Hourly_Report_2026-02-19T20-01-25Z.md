# Honeypot Attack Report - 2026-02-19T20:00:16Z

**Executive Summary:**
- Over the past hour, a total of 4,897 attacks were recorded.
- The majority of attacks originated from Germany (1,918) and the United States (1,116).
- The most prominent attacker IP was 207.154.239.37 with 770 attacks.
- A significant portion of attacks (2,509) were categorized as "Misc activity".
- The most frequent alert signature was "GPL INFO VNC server response" with 2,324 occurrences.
- Common usernames and passwords like "git", "guest", "123456", and "password" were frequently used in brute-force attempts.

**Detailed Analysis:**

**Total Attacks:**
- 4,897

**Top Attacking Countries:**
- Germany: 1,918
- United States: 1,116
- Australia: 830
- Singapore: 391
- Netherlands: 104

**Notable IP Reputations:**
- known attacker: 1,386
- mass scanner: 186
- tor exit node: 6

**Common Alert Categories:**
- Misc activity: 2,509
- Generic Protocol Command Decode: 509
- Misc Attack: 411
- Attempted Information Leak: 85
- Attempted Administrator Privilege Gain: 39
- Potentially Bad Traffic: 15
- access to a potentially vulnerable web application: 4
- Detection of a Network Scan: 3
- Not Suspicious Traffic: 3
- A Network Trojan was detected: 2

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 2,324
- 2200003 - SURICATA IPv4 truncated packet: 189
- 2200122 - SURICATA AF-PACKET truncated packet: 189
- 2402000 - ET DROP Dshield Block Listed Source group 1: 133
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 85
- 2001978 - ET INFO SSH session in progress on Expected Port: 72
- 2009582 - ET SCAN NMAP -sS window 1024: 42
- 2102044 - GPL INFO PPTP Start Control Request attempt: 34
- 2001219 - ET SCAN Potential SSH Scan: 27
- 2210048 - SURICATA STREAM reassembly sequence GAP -- missing packet(s): 24

**ASN Information:**
- 14061 - DigitalOcean, LLC: 3,071
- 8075 - Microsoft Corporation: 414
- 396982 - Google LLC: 225
- 174 - Cogent Communications, LLC: 210
- 213412 - ONYPHE SAS: 124
- 46783 - EASY LINK LLC: 81
- 135377 - UCLOUD INFORMATION TECHNOLOGY HK LIMITED: 66
- 16509 - Amazon.com, Inc.: 58
- 209334 - Modat B.V.: 58
- 398324 - Censys, Inc.: 46

**Source IP Addresses:**
- 207.154.239.37: 770
- 104.248.249.212: 570
- 165.227.161.214: 497
- 134.199.173.128: 455
- 4.145.113.4: 382
- 134.199.153.94: 375
- 38.255.17.80: 81
- 2.57.122.96: 40
- 142.93.3.176: 39
- 207.90.244.22: 35

**Country to Port Mapping:**
- **Australia**
  - 22: 166
- **Canada**
  - 8728: 6
  - 9084: 3
  - 1070: 1
  - 1112: 1
  - 1206: 1
  - 1322: 1
  - 1406: 1
  - 1446: 1
  - 1562: 1
  - 1616: 1
- **China**
  - 9000: 12
  - 6379: 6
  - 9200: 6
  - 11300: 6
  - 4200: 5
  - 9080: 5
  - 13720: 5
  - 22: 4
  - 10124: 4
  - 18017: 4
- **France**
  - 10001: 4
  - 1024: 2
  - 1680: 2
  - 3127: 2
  - 3128: 2
  - 3489: 2
  - 4001: 2
  - 4081: 2
  - 4431: 2
  - 4500: 2
- **Germany**
  - 22: 367
  - 1723: 34
  - 32810: 8
  - 3000: 4
  - 6030: 4
  - 6133: 4
  - 8033: 4
  - 58895: 4
  - 3131: 3
  - 8412: 3
- **Hong Kong**
  - 8000: 10
  - 20202: 10
  - 9530: 6
  - 23: 1
  - 80: 1
  - 6047: 1
  - 10471: 1
  - 26004: 1
  - 32121: 1
- **Netherlands**
  - 9100: 24
  - 80: 11
  - 6036: 8
  - 22: 6
  - 6037: 4
  - 17000: 4
  - 10083: 3
  - 16404: 3
  - 18182: 3
  - 25: 2
- **Singapore**
  - 5903: 39
  - 5905: 39
  - 5901: 38
  - 5902: 38
  - 5904: 38
  - 5906: 38
  - 5907: 38
  - 5908: 38
  - 5909: 38
  - 5910: 38
- **United Kingdom**
  - 11479: 7
  - 13389: 4
  - 3016: 3
  - 3105: 3
  - 5255: 3
  - 9152: 3
  - 10022: 3
  - 3008: 2
  - 18778: 2
  - 28139: 2
- **United States**
  - 3399: 42
  - 9200: 20
  - 22: 18
  - 26080: 10
  - 445: 8
  - 9999: 8
  - 10001: 8
  - 25: 7
  - 4443: 7
  - 9050: 7

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2025-55182 CVE-2025-55182: 2
- CVE-2019-11500 CVE-2019-11500: 1

**Usernames:**
- git: 43
- guest: 36
- elastic: 34
- ftpuser: 33
- docker: 31
- mysql: 26
- elasticsearch: 24
- es: 24
- ftptest: 24
- dspace: 22

**Passwords:**
- 123456: 43
- password: 43
- qwerty: 40
- welcome: 23
- 12345: 21
- 123456789: 21
- letmein: 21
- 1234567: 20
- 12345678: 20
- abc123: 12

**OS Distribution:**
- Linux 2.2.x-3.x: 17,398
- Windows NT kernel 5.x: 9,494
- Linux 2.2.x-3.x (barebone): 565
- Windows NT kernel: 457
- Linux 2.2.x-3.x (no timestamps): 137
- Linux 3.11 and newer: 92
- Mac OS X: 63
- Windows 7 or 8: 5
- Linux 3.x: 5
- Nintendo 3DS: 1

**Hyper-aggressive IPs:**
- 207.154.239.37: 770 attacks
- 104.248.249.212: 570 attacks
- 165.227.161.214: 497 attacks
- 134.199.173.128: 455 attacks
- 4.145.113.4: 382 attacks
- 134.199.153.94: 375 attacks
