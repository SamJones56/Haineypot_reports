# Honeypot Attack Report - 2026-02-24T04:00:25Z

## Executive Summary:
- Over the past hour, a total of 3,237 attacks were observed.
- The majority of attacks originated from the United States, accounting for 1,684 incidents, with DigitalOcean, LLC being the most prominent ASN.
- The most frequent alert signature was "SURICATA IPv4 truncated packet" with 777 occurrences.
- A significant number of attacks were categorized as "Generic Protocol Command Decode".
- The most targeted services were SSH (port 22) and VNC (ports 5901, 5902, 5903).
- The most common credentials used were "admin" and "daemon" for usernames, and "1234" and "123456" for passwords.

## Detailed Analysis:

**Total Attacks:**
- 3,237

**Top Attacking Countries:**
- United States: 1,684
- United Kingdom: 509
- Vietnam: 235
- Romania: 232
- Switzerland: 188

**Notable IP Reputations:**
- known attacker: 1,468
- mass scanner: 126
- tor exit node: 1

**Common Alert Categories:**
- Generic Protocol Command Decode: 1,866
- Misc activity: 488
- Misc Attack: 320
- Attempted Information Leak: 58
- Potentially Bad Traffic: 29
- Detection of a Network Scan: 10
- Attempted Administrator Privilege Gain: 9
- Potential Corporate Privacy Violation: 3
- Detection of a Denial of Service Attack: 2
- Web Application Attack: 2

**Alert Signatures:**
- 2200003, SURICATA IPv4 truncated packet: 777
- 2200122, SURICATA AF-PACKET truncated packet: 777
- 2228000, SURICATA SSH invalid banner: 220
- 2100560, GPL INFO VNC server response: 218
- 2001984, ET INFO SSH session in progress on Unusual Port: 101
- 2402000, ET DROP Dshield Block Listed Source group 1: 97
- 2038967, ET INFO SSH-2.0-Go version string Observed in Network Traffic: 86
- 2001978, ET INFO SSH session in progress on Expected Port: 71
- 2009582, ET SCAN NMAP -sS window 1024: 46
- 2260002, SURICATA Applayer Detect protocol only one direction: 18

**ASN Information:**
- 14061, DigitalOcean, LLC: 1,328
- 47890, Unmanaged Ltd: 407
- 131427, AOHOAVIET: 235
- 51852, Private Layer INC: 188
- 396982, Google LLC: 171
- 202425, IP Volume inc: 125
- 16509, Amazon.com, Inc.: 112
- 4808, China Unicom Beijing Province Network: 54
- 48090, Techoff Srv Limited: 51
- 398324, Censys, Inc.: 51

**Source IP Addresses:**
- 162.243.37.252: 545
- 157.245.36.181: 475
- 103.53.231.159: 235
- 46.19.137.194: 188
- 2.57.122.96: 170
- 129.212.184.194: 113
- 185.242.226.45: 81
- 134.199.197.108: 58
- 165.245.138.210: 53
- 123.117.152.245: 48

**Country to Port Mapping:**
- **Romania**
  - 22: 37
  - 1900: 2
  - 8863: 2
  - 11736: 2
  - 30711: 2
- **Switzerland**
  - 5436: 166
  - 15433: 20
  - 5432: 2
- **United Kingdom**
  - 22: 95
  - 443: 6
  - 80: 3
  - 5432: 3
  - 1912: 1
- **United States**
  - 22: 121
  - 5902: 115
  - 5901: 93
  - 5903: 58
  - 10000: 42
- **Vietnam**
  - 22: 47

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 6
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2023-26801 CVE-2023-26801: 1
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- admin: 47
- daemon: 47
- user: 38
- guest: 33
- elastic: 13
- es: 13
- ftptest: 13
- gerrit: 13
- git: 13
- sol: 13

**Passwords:**
- 1234: 14
- 123456: 13
- 123456789: 12
- password: 12
- 12345: 11
- 12345678: 11
- passw0rd: 10
- 1: 9
- 123: 9
- 1234567: 9

**OS Distribution:**
- Linux 2.2.x-3.x: 10,327
- Windows NT kernel: 7,575
- Linux 2.2.x-3.x (barebone): 342
- Linux 2.2.x-3.x (no timestamps): 259
- Windows NT kernel 5.x: 148
- Linux 3.11 and newer: 22
- Mac OS X: 5
- Windows 7 or 8: 4
- FreeBSD: 1
- Linux 2.4.x-2.6.x: 1

**Hyper-aggressive IPs:**
- 162.243.37.252: 545 attacks
