# Honeypot Attack Report - 2026-02-21T11:00:14Z

## Executive Summary:
- **High Attack Volume:** A total of 1677 attacks were observed in the past hour, with the majority originating from the United States.
- **Dominant Attacker:** The most active attacker was 34.158.168.101, associated with Google LLC, responsible for 193 attacks.
- **Common Tactics:** The most frequent alert category was "Generic Protocol Command Decode," and the most common alert signature was "SURICATA SSH invalid banner."
- **Exploitation Attempts:** Several CVEs were targeted, including CVE-2021-3449 and CVE-2024-14007.
- **Credential Stuffing:** The most common username attempted was "root," and common passwords such as "123456" and "password" were used.
- **Attacker Infrastructure:** The majority of attacks came from known attackers and mass scanners, with a significant portion of the infrastructure hosted by Google LLC.

## Detailed Analysis:

**Total Attacks:**
- 1677

**Top Attacking Countries:**
- United States: 687
- Netherlands: 244
- Vietnam: 174
- Switzerland: 154
- United Kingdom: 77

**Notable IP Reputations:**
- known attacker: 1156
- mass scanner: 132
- bot, crawler: 2

**Common Alert Categories:**
- Generic Protocol Command Decode: 484
- Misc activity: 404
- Misc Attack: 328
- Attempted Information Leak: 81
- Potentially Bad Traffic: 20
- Attempted Administrator Privilege Gain: 7
- Detection of a Network Scan: 4
- Detection of a Denial of Service Attack: 3
- Web Application Attack: 3
- access to a potentially vulnerable web application: 1

**Alert Signatures:**
- 2228000 - SURICATA SSH invalid banner: 241
- 2100560 - GPL INFO VNC server response: 226
- 2001984 - ET INFO SSH session in progress on Unusual Port: 116
- 2402000 - ET DROP Dshield Block Listed Source group 1: 101
- 2200003 - SURICATA IPv4 truncated packet: 48
- 2200122 - SURICATA AF-PACKET truncated packet: 48
- 2009582 - ET SCAN NMAP -sS window 1024: 45
- 2210044 - SURICATA STREAM Packet with invalid timestamp: 26
- 2001978 - ET INFO SSH session in progress on Expected Port: 25
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 23

**ASN Information:**
- 396982 - Google LLC: 328
- 47890 - Unmanaged Ltd: 209
- 131427 - AOHOAVIET: 174
- 51852 - Private Layer INC: 154
- 202425 - IP Volume inc: 107
- 135377 - UCLOUD INFORMATION TECHNOLOGY HK LIMITED: 71
- 6939 - Hurricane Electric LLC: 61
- 63949 - Akamai Connected Cloud: 59
- 14061 - DigitalOcean, LLC: 47
- 398324 - Censys, Inc.: 45

**Source IP Addresses:**
- 34.158.168.101: 193
- 103.53.231.159: 174
- 46.19.137.194: 154
- 185.242.226.40: 40
- 185.242.226.46: 32
- 45.33.110.167: 29
- 5.61.209.92: 24
- 92.118.39.115: 24
- 92.118.39.180: 24
- 92.118.39.84: 24

**Country to Port Mapping:**
- France:
  - 3128: 3
  - 2161: 2
  - 3401: 2
  - 4095: 2
  - 4444: 2
  - 6471: 2
  - 7101: 2
  - 7631: 2
  - 7668: 2
  - 7778: 2
- Germany:
  - 44300: 10
  - 34225: 7
  - 28796: 4
  - 49152: 4
  - 57691: 4
  - 61086: 4
  - 9593: 3
  - 2705: 2
  - 4257: 2
  - 8081: 2
- Netherlands:
  - 443: 189
  - 27017: 22
  - 8728: 7
  - 3005: 4
  - 80: 3
  - 22: 2
  - 8001: 2
  - 8500: 2
  - 8545: 2
  - 4433: 1
- Portugal:
  - 12345: 10
  - 32400: 10
  - 22: 1
  - 35000: 1
- Romania:
  - 22: 2
  - 5524: 2
  - 13431: 2
  - 13636: 2
  - 21995: 2
  - 24072: 2
  - 26250: 2
  - 27508: 2
  - 30285: 2
  - 31535: 2
- Seychelles:
  - 6037: 8
  - 9100: 8
  - 17001: 8
  - 5253: 1
- Switzerland:
  - 5434: 153
  - 5432: 1
- United Kingdom:
  - 1139: 7
  - 3391: 4
  - 7190: 4
  - 5432: 3
  - 3306: 2
  - 4528: 2
  - 5762: 2
  - 7593: 2
  - 8044: 2
  - 9997: 2
- United States:
  - 5901: 41
  - 1434: 35
  - 3205: 32
  - 445: 29
  - 8883: 21
  - 9200: 20
  - 8728: 13
  - 80: 9
  - 25: 8
  - 2082: 6
- Vietnam:
  - 22: 34

**CVEs Exploited:**
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2023-46604 CVE-2023-46604 CVE-2023-46604: 2
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- root: 39
- user: 5
- postgres: 4

**Passwords:**
- 123456: 3
- password: 3
- : 2
- 123: 2
- 12345: 2
- 12345678: 2
- Password: 2
- Password1: 2
- Password@123: 2
- Qwerty: 2

**OS Distribution:**
- Linux 2.2.x-3.x: 13513
- Windows NT kernel: 12242
- Linux 2.2.x-3.x (barebone): 309
- Windows NT kernel 5.x: 131
- Linux 2.2.x-3.x (no timestamps): 237
- Linux 3.11 and newer: 41
- Mac OS X: 72
- Windows XP: 3
- FreeBSD: 2
- Linux 3.x: 2

**Hyper-aggressive IPs:**
- 34.158.168.101: 193
- 103.53.231.159: 174
- 46.19.137.194: 154
