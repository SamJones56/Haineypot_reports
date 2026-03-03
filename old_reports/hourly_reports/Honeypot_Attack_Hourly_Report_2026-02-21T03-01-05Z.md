# Honeypot Attack Report - 2026-02-21T03:00:22Z

## Executive Summary:
- **High Attack Volume:** A total of 2,287 attacks were observed in the past hour.
- **Dominant Attacker:** The most active attacker was from the United States, with 906 attacks.
- **Hyper-aggressive IPs:** The IP address 178.20.210.32, associated with ASN 210006 (Shereverov Marat Ahmedovich), was responsible for 405 attacks.
- **Common Attack Vector:** The most common alert category was "Generic Protocol Command Decode" with 911 instances.
- **Credential Stuffing:** Brute-force attempts were prevalent, with "sa" and "root" being the most frequently used usernames.
- **Vulnerability Scanning:** The most scanned for CVE was CVE-2025-55182.

## Detailed Analysis:

**Total Attacks:**
- 2,287

**Top Attacking Countries:**
- United States: 906
- Germany: 450
- Canada: 164
- United Kingdom: 108
- China: 87

**Notable IP Reputations:**
- known attacker: 1,723
- mass scanner: 131

**Common Alert Categories:**
- Generic Protocol Command Decode: 911
- Misc activity: 398
- Misc Attack: 361
- Attempted Information Leak: 60
- Potentially Bad Traffic: 50

**Alert Signatures:**
- 2200003 - SURICATA IPv4 truncated packet: 249
- 2200122 - SURICATA AF-PACKET truncated packet: 249
- 2100560 - GPL INFO VNC server response: 230
- 2228000 - SURICATA SSH invalid banner: 227
- 2001984 - ET INFO SSH session in progress on Unusual Port: 112

**ASN Information:**
- 210006 - Shereverov Marat Ahmedovich: 405
- 396982 - Google LLC: 228
- 47890 - Unmanaged Ltd: 195
- 209334 - Modat B.V.: 154
- 16509 - Amazon.com, Inc.: 131

**Source IP Addresses:**
- 178.20.210.32: 405
- 46.19.137.194: 77
- 172.86.126.140: 63
- 172.86.127.82: 63
- 18.116.101.220: 46

**Country to Port Mapping:**
- Canada
  - 3311: 3
  - 8728: 3
  - 2945: 2
  - 6725: 2
  - 7359: 2
- China
  - 1433: 35
  - 23: 19
  - 5902: 5
  - 3790: 4
  - 18090: 4
- Germany
  - 22: 81
  - 9209: 4
  - 9928: 4
  - 10923: 4
  - 17918: 4
- United Kingdom
  - 9100: 9
  - 1417: 8
  - 80: 2
  - 1034: 2
  - 1234: 2
- United States
  - 44818: 39
  - 8728: 28
  - 1025: 18
  - 8291: 16
  - 8180: 12

**CVEs Exploited:**
- CVE-2025-55182 CVE-2025-55182: 6
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2002-0013 CVE-2002-0012: 1

**Usernames:**
- sa: 34
- root: 29
- admin: 9
- user: 7
- ftp: 4
- git: 4
- dave: 3
- mongodb: 3
- peter: 3
- pi: 3

**Passwords:**
- : 10
- test123: 5
- 12345: 3
- 123456: 3
- 1qaz2wsx: 3

**OS Distribution:**
- Linux 2.2.x-3.x: 5,270
- Windows NT kernel: 3,771
- Linux 2.2.x-3.x (barebone): 285
- Windows NT kernel 5.x: 185
- Linux 3.11 and newer: 36

**Hyper-aggressive IPs:**
- 178.20.210.32: 405
- 46.19.137.194: 77
- 172.86.126.140: 63
- 172.86.127.82: 63
