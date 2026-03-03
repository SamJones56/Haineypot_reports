# Honeypot Attack Report - 2026-02-21T15:00:16Z

**Executive Summary:**
- A total of 3,504 attacks were observed in the past hour.
- The majority of attacks originated from Singapore, with a single IP address (128.199.198.62) from this region responsible for 1,478 attacks.
- The most common attack vector was SSH, with "SURICATA SSH invalid banner" being the most frequent alert signature.
- The most common username and password combination was "root" with a blank password, indicating widespread brute-force attempts.
- The dominant operating systems of attacking machines were Linux and Windows NT.
- Several CVEs were exploited, with CVE-2021-3449 being the most frequent.

**Detailed Analysis:**

**Total Attacks:**
- 3,504

**Top Attacking Countries:**
- Singapore: 1,483
- United States: 789
- Germany: 396
- Switzerland: 183
- United Kingdom: 119

**Notable IP Reputations:**
- known attacker: 2,945
- mass scanner: 139
- bot, crawler: 2

**Common Alert Categories:**
- Misc activity: 445
- Generic Protocol Command Decode: 436
- Misc Attack: 374
- Attempted Information Leak: 102
- Potentially Bad Traffic: 15
- Attempted Administrator Privilege Gain: 14
- Detection of a Network Scan: 4
- Detection of a Denial of Service Attack: 3
- Web Application Attack: 2
- access to a potentially vulnerable web application: 1

**Alert Signatures:**
- 2228000 SURICATA SSH invalid banner: 226
- 2100560 GPL INFO VNC server response: 222
- 2402000 ET DROP Dshield Block Listed Source group 1: 98
- 2001984 ET INFO SSH session in progress on Unusual Port: 96
- 2038967 ET INFO SSH-2.0-Go version string Observed in Network Traffic: 60
- 2001978 ET INFO SSH session in progress on Expected Port: 56
- 2200003 SURICATA IPv4 truncated packet: 51
- 2200122 SURICATA AF-PACKET truncated packet: 51
- 2009582 ET SCAN NMAP -sS window 1024: 46
- 2210051 SURICATA STREAM Packet with broken ack: 31

**ASN Information:**
- 14061 DigitalOcean, LLC: 1,619
- 210006 Shereverov Marat Ahmedovich: 369
- 47890 Unmanaged Ltd: 309
- 8075 Microsoft Corporation: 209
- 396982 Google LLC: 119
- 131427 AOHOAVIET: 75
- 138298 A2j Data Services Pvt. Ltd.: 71
- 48090 Techoff Srv Limited: 67
- 135377 UCLOUD INFORMATION TECHNOLOGY HK LIMITED: 63
- 213412 ONYPHE SAS: 58

**Source IP Addresses:**
- 128.199.198.62: 1,478
- 178.20.210.32: 355
- 20.203.180.135: 176
- 92.118.39.95: 101
- 129.212.184.194: 86
- 103.53.231.159: 75
- 103.215.201.34: 71
- 45.148.10.121: 52
- 45.79.223.191: 39
- 167.99.8.194: 28

**Country to Port Mapping:**
- France
  - 23: 4
  - 3306: 4
  - 8291: 4
  - 3128: 3
  - 2078: 2
  - 2080: 2
  - 2375: 2
  - 2500: 2
  - 4001: 2
  - 4136: 2
- Germany
  - 22: 71
  - 5580: 8
  - 8631: 4
  - 2375: 2
  - 6287: 2
  - 8542: 2
  - 14569: 2
  - 22475: 2
  - 23000: 2
  - 23209: 2
- India
  - 3306: 71
  - 32211: 8
  - 2083: 1
- Netherlands
  - 80: 16
  - 22: 9
  - 9000: 5
  - 6036: 4
  - 25565: 3
  - 81: 2
  - 5601: 2
  - 443: 1
  - 3128: 1
  - 8545: 1
- Romania
    - 22: 4
    - 5215: 2
    - 5842: 2
    - 7590: 2
    - 10910: 2
    - 15338: 2
    - 18751: 2
    - 26486: 2
    - 27060: 2
    - 33276: 2
- Singapore
  - 22: 296
  - 2082: 3
  - 80: 2
- Switzerland
  - 80: 176
  - 8123: 2
  - 22: 1
  - 33322: 1
- United Kingdom
  - 9090: 14
  - 8004: 4
  - 23390: 4
  - 80: 3
  - 1045: 2
  - 1523: 2
  - 3441: 2
  - 3467: 2
  - 3534: 2
  - 4010: 2
- United States
  - 5902: 86
  - 3388: 46
  - 22: 31
  - 8983: 14
  - 10000: 11
  - 8333: 10
  - 25: 8
  - 17000: 8
  - 20000: 8
  - 3531: 7
- Vietnam
  - 22: 15

**CVEs Exploited:**
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2023-46604 CVE-2023-46604 CVE-2023-46604: 2
- CVE-2024-14007 CVE-2024-14007: 2
- CVE-2002-0013 CVE-2002-0012: 1
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- root: 402
- user: 9
- admin: 8
- mohammed: 8
- james: 7
- sol: 5
- ftpuser: 4
- oxidized: 3
- 2020: 2
- collins: 2

**Passwords:**
- : 76
- 123456: 9
- 1234: 7
- admin: 7
- 123: 6
- 1: 3
- 12345678: 3
- root: 3
- 12345: 2
- 2020: 2

**OS Distribution:**
- Linux 2.2.x-3.x: 13,066
- Windows NT kernel: 11,999
- Linux 2.2.x-3.x (barebone): 277
- Windows NT kernel 5.x: 152
- Linux 2.2.x-3.x (no timestamps): 167
- Linux 3.11 and newer: 31
- Mac OS X: 15
- Linux 3.x: 2
- Windows XP: 2
- Linux 3.1-3.10: 3

**Hyper-aggressive IPs:**
- 128.199.198.62: 1,478
- 178.20.210.32: 355
- 20.203.180.135: 176
- 92.118.39.95: 101
