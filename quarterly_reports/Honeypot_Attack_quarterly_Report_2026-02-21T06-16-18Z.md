# Honeypot Attack Report - 2026-02-21T06:15:14Z

## Executive Summary:
- Over the past 6 hours, there have been a total of 21,042 attacks.
- The majority of attacks originated from the United States, followed by Canada and India.
- The most prominent attacker ASN is 14061 (DigitalOcean, LLC), responsible for 6,301 attacks.
- The most frequent alert signatures were "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet", each with 4,363 occurrences.
- Common credential stuffing attacks involved the username "root" and the password "123456".
- Several CVEs were observed, with CVE-2024-14007 being the most frequent.

## Detailed Analysis:

**Total Attacks:**
- 21042

**Top Attacking Countries:**
- United States: 5796
- Canada: 3275
- India: 3078
- Germany: 2402
- United Kingdom: 1331

**Notable IP Reputations:**
- known attacker: 10629
- mass scanner: 972
- bot, crawler: 1

**Common Alert Categories:**
- Generic Protocol Command Decode: 11151
- Misc activity: 2530
- Misc Attack: 2269
- Attempted Administrator Privilege Gain: 1543
- Attempted Information Leak: 412
- Potentially Bad Traffic: 187
- Web Application Attack: 48
- Detection of a Network Scan: 21
- access to a potentially vulnerable web application: 18
- A Network Trojan was detected: 14

**Alert Signatures:**
- 2200003, SURICATA IPv4 truncated packet: 4363
- 2200122, SURICATA AF-PACKET truncated packet: 4363
- 2024766, ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1484
- 2100560, GPL INFO VNC server response: 1352
- 2228000, SURICATA SSH invalid banner: 1336
- 2402000, ET DROP Dshield Block Listed Source group 1: 688
- 2001984, ET INFO SSH session in progress on Unusual Port: 647
- 2009582, ET SCAN NMAP -sS window 1024: 265
- 2001978, ET INFO SSH session in progress on Expected Port: 232
- 2038967, ET INFO SSH-2.0-Go version string Observed in Network Traffic: 220

**ASN Information:**
- 14061, DigitalOcean, LLC: 6301
- 210006, Shereverov Marat Ahmedovich: 2110
- 47890, Unmanaged Ltd: 1618
- 396982, Google LLC: 1593
- 51852, Private Layer INC: 905
- 4134, Chinanet: 839
- 14956, RouterHosting LLC: 750
- 209334, Modat B.V.: 658
- 16509, Amazon.com, Inc.: 574
- 202425, IP Volume inc: 527

**Source IP Addresses:**
- 167.71.234.239: 2507
- 146.190.242.202: 2504
- 178.20.210.32: 2110
- 46.19.137.194: 905
- 124.225.88.153: 790
- 134.209.180.181: 773
- 103.79.11.171: 388
- 172.86.127.82: 372
- 172.86.126.140: 369
- 86.54.24.29: 351

**Country to Port Mapping:**
- Canada
  - 22: 508
  - 8728: 26
  - 80: 8
  - 8178: 5
  - 2214: 4
- China
  - 23: 423
  - 1433: 35
  - 50100: 14
  - 7780: 9
  - 58603: 7
- Germany
  - 22: 423
  - 20000: 40
  - 50000: 10
  - 5521: 8
  - 28866: 8
- India
  - 22: 499
  - 445: 388
  - 80: 108
  - 443: 67
  - 23: 4
- Latvia
  - 22: 71
- Netherlands
  - 443: 186
  - 8728: 42
  - 6037: 32
  - 9100: 32
  - 17000: 32
- Romania
  - 22: 109
  - 587: 2
  - 1198: 2
  - 3298: 2
  - 3740: 2
- Switzerland
  - 5434: 443
  - 15432: 340
  - 5444: 106
  - 5432: 16
- United Kingdom
  - 22: 152
  - 7000: 12
  - 9100: 9
  - 1417: 8
  - 1419: 8
- United States
  - 9093: 116
  - 80: 105
  - 8728: 77
  - 445: 69
  - 9200: 42

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 20
- CVE-2025-55182 CVE-2025-55182: 17
- CVE-2021-3449 CVE-2021-3449: 8
- CVE-2006-2369: 5
- CVE-2019-11500 CVE-2019-11500: 5
- CVE-2024-4577 CVE-2002-0953: 4
- CVE-2024-4577 CVE-2024-4577: 4
- CVE-2002-0013 CVE-2002-0012: 2
- CVE-2010-0569: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 2

**Usernames:**
- root: 353
- admin: 129
- user: 91
- ubuntu: 40
- sa: 34
- postgres: 30
- deploy: 29
- ftp: 27
- test: 27
- ftpuser: 18

**Passwords:**
- 123456: 144
- password: 58
- 123: 50
- P@ssw0rd: 32
- 1234: 29
- : 27
- admin: 26
- 12345678: 20
- p@ssw0rd: 19
- 12345: 18

**OS Distribution:**
- Linux 2.2.x-3.x: 40370
- Windows NT kernel: 29797
- Linux 2.2.x-3.x (barebone): 2138
- Windows NT kernel 5.x: 926
- Linux 2.2.x-3.x (no timestamps): 874
- Windows 7 or 8: 457
- Linux 3.11 and newer: 212
- Mac OS X: 82
- Linux 3.1-3.10: 61
- Linux 2.4.x: 5

**Hyper-aggressive IPs:**
- 167.71.234.239: 2507
- 146.190.242.202: 2504
- 178.20.210.32: 2110
