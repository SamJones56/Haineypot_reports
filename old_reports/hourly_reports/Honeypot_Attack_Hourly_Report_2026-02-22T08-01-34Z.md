# Honeypot Attack Report - 2026-02-22T08:00:16Z

## Executive Summary:
- **High Volume Attack Activity:** A total of 3,838 attacks were observed in the past hour, with the United States being the most prominent source, accounting for 1,708 of these attacks.
- **Dominant Attacker Infrastructure:** DigitalOcean, LLC (ASN 14061) was the top attacking ASN with 1,081 attacks. The most aggressive IP, 59.145.41.149, originated from BHARTI Airtel Ltd. (ASN 9498) in India.
- **Common Attack Vectors:** The most frequent alert signatures were "SURICATA SSH invalid banner" (262 occurrences) and "GPL INFO VNC server response" (220 occurrences). "Generic Protocol Command Decode" and "Misc activity" were the most common alert categories, each with 490 alerts.
- **Exploitation and Credential Stuffing:** There were attempts to exploit CVE-2024-14007 and CVE-2025-55182. Brute force attempts were prevalent, with "root" being the most targeted username (94 attempts) and "123456" the most common password (16 attempts).
- **Attacker Landscape:** The vast majority of attacking systems were identified as running Linux, with "Linux 2.2.x-3.x" being the most common OS distribution. A significant portion of attacking IPs (1,778) are known attackers.
- **Targeted Ports:** Port 445 in India and port 5902 in the United States were the most targeted, with 370 and 113 attacks respectively.

## Detailed Analysis:

**Total Attacks:**
- 3838

**Top Attacking Countries:**
- United States: 1708
- India: 495
- Romania: 441
- Netherlands: 292
- Germany: 272

**Notable IP Reputations:**
- known attacker: 1778
- mass scanner: 174
- bot, crawler: 3

**Common Alert Categories:**
- Generic Protocol Command Decode: 490
- Misc activity: 490
- Misc Attack: 398
- Attempted Information Leak: 65
- Potentially Bad Traffic: 23
- Detection of a Network Scan: 5
- Attempted Administrator Privilege Gain: 4
- Web Application Attack: 3
- access to a potentially vulnerable web application: 2
- Not Suspicious Traffic: 1

**Alert Signatures:**
- 2228000, SURICATA SSH invalid banner: 262
- 2100560, GPL INFO VNC server response: 220
- 2001984, ET INFO SSH session in progress on Unusual Port: 121
- 2402000, ET DROP Dshield Block Listed Source group 1: 120
- 2001978, ET INFO SSH session in progress on Expected Port: 79
- 2038967, ET INFO SSH-2.0-Go version string Observed in Network Traffic: 59
- 2200003, SURICATA IPv4 truncated packet: 49
- 2200122, SURICATA AF-PACKET truncated packet: 49
- 2009582, ET SCAN NMAP -sS window 1024: 44
- 2230002, SURICATA TLS invalid record type: 24

**ASN Information:**
- 14061, DigitalOcean, LLC: 1081
- 47890, Unmanaged Ltd: 628
- 9498, BHARTI Airtel Ltd.: 370
- 396982, Google LLC: 335
- 16509, Amazon.com, Inc.: 205
- 20473, The Constant Company, LLC: 164
- 209334, Modat B.V.: 136
- 202425, IP Volume inc: 121
- 51852, Private Layer INC: 92
- 398324, Censys, Inc.: 74

**Source IP Addresses:**
- 59.145.41.149: 370
- 165.22.2.4: 304
- 2.57.122.208: 220
- 165.22.26.70: 198
- 142.93.234.28: 125
- 143.110.179.223: 125
- 129.212.184.194: 113
- 2.57.122.96: 95
- 34.158.168.101: 95
- 46.19.137.194: 92

**Country to Port Mapping:**
- Canada
  - 1125: 2
  - 1529: 2
  - 2456: 2
  - 2566: 2
  - 2621: 2
- Germany
  - 22: 39
  - 8000: 24
  - 4000: 10
  - 443: 6
  - 8081: 4
- India
  - 445: 370
  - 22: 25
- Japan
  - 23: 23
- Netherlands
  - 443: 93
  - 22: 25
  - 1337: 20
  - 6036: 8
  - 6037: 8
- Poland
  - 23: 13
  - 8090: 4
  - 8091: 4
  - 3629: 2
- Romania
  - 22: 82
  - 6001: 2
  - 10399: 2
  - 16855: 2
  - 20655: 2
- Switzerland
  - 54322: 90
  - 5432: 2
- United Kingdom
  - 443: 4
  - 80: 2
  - 7000: 2
  - 9099: 2
  - 12080: 2
- United States
  - 5902: 113
  - 22: 71
  - 5901: 60
  - 3391: 57
  - 5903: 57

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2025-55182 CVE-2025-55182: 2

**Usernames:**
- root: 94
- master: 26
- admin: 23
- es: 23
- ubuntu: 22
- solana: 15
- sol: 12
- support: 5
- solv: 4
- trader: 4

**Passwords:**
- 123456: 16
- 1234: 13
- 123: 10
- 12345: 8
- 12345678: 8
- 1234567890: 8
- password: 8
- 1: 7
- 123456789: 7
- passw0rd: 7

**OS Distribution:**
- Linux 2.2.x-3.x: 10590
- Linux 2.2.x-3.x (barebone): 332
- Windows NT kernel 5.x: 156
- Linux 3.11 and newer: 49
- Linux 2.2.x-3.x (no timestamps): 234
- Windows NT kernel: 25
- Mac OS X: 16
- Linux 3.1-3.10: 14
- FreeBSD: 1
- Linux 3.x: 1

**Hyper-aggressive IPs:**
- 59.145.41.149: 370
- 165.22.2.4: 304
- 2.57.122.208: 220
- 165.22.26.70: 198
- 142.93.234.28: 125
- 143.110.179.223: 125
- 129.212.184.194: 113
