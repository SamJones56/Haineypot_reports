# Honeypot Attack Report - 2026-02-21T08:00:13Z

## Executive Summary:
- **High Attack Volume:** A total of 1,493 attacks were observed in the past hour.
- **Dominant Actor:** The United States was the top attacking country, responsible for 766 attacks, more than half of the total volume.
- **Credential Stuffing:** Brute-force attempts were prevalent, with "root" (95 attempts) and "sa" (41 attempts) being the most targeted usernames. A significant number of attempts (91) used an empty password.
- **VNC Exploitation:** The most frequent alert signature was "GPL INFO VNC server response" with 338 occurrences, indicating widespread scanning and exploitation attempts targeting VNC servers.
- **Hyper-Aggressive IPs:** Two IP addresses, 152.42.187.194 (86 attacks) and 46.19.137.194 (61 attacks), exhibited hyper-aggressive behavior, accounting for a significant portion of the attacks.
- **Known Attackers:** A large number of attacks (867) originated from IPs with a reputation of "known attacker".

## Detailed Analysis:

**Total Attacks:**
- 1,493

**Top Attacking Countries:**
- United States: 766
- Netherlands: 94
- Singapore: 92
- China: 63
- Switzerland: 61

**Notable IP Reputations:**
- known attacker: 867
- mass scanner: 212

**Common Alert Categories:**
- Generic Protocol Command Decode: 753
- Misc activity: 529
- Misc Attack: 352
- Potentially Bad Traffic: 104
- Attempted Information Leak: 61
- Attempted Administrator Privilege Gain: 60
- Not Suspicious Traffic: 3
- Successful Administrator Privilege Gain: 3
- Detection of a Network Scan: 2
- access to a potentially vulnerable web application: 2

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 338
- 2200003 - SURICATA IPv4 truncated packet: 231
- 2200122 - SURICATA AF-PACKET truncated packet: 231
- 2228000 - SURICATA SSH invalid banner: 191
- 2402000 - ET DROP Dshield Block Listed Source group 1: 101
- 2001984 - ET INFO SSH session in progress on Unusual Port: 97
- 2002923 - ET EXPLOIT VNC Server Not Requiring Authentication (case 2): 56
- 2010937 - ET SCAN Suspicious inbound to mySQL port 3306: 56
- 2002920 - ET INFO VNC Authentication Failure: 55
- 2010935 - ET SCAN Suspicious inbound to MSSQL port 1433: 45

**ASN Information:**
- 396982 (Google LLC): 221
- 14061 (DigitalOcean, LLC): 215
- 47890 (Unmanaged Ltd): 166
- 398324 (Censys, Inc.): 81
- 16509 (Amazon.com, Inc.): 72
- 51852 (Private Layer INC): 61
- 206264 (Amarutu Technology Ltd): 56
- 135377 (UCLOUD INFORMATION TECHNOLOGY HK LIMITED): 51
- 6939 (Hurricane Electric LLC): 49
- 202425 (IP Volume inc): 49

**Source IP Addresses:**
- 152.42.187.194: 86
- 46.19.137.194: 61
- 112.1.26.107: 42
- 192.241.134.238: 33
- 185.242.226.39: 32
- 5.61.209.92: 24
- 144.172.88.33: 23
- 16.58.56.214: 23
- 92.118.39.84: 22
- 206.189.227.8: 21

**Country to Port Mapping:**
- **Belgium**
  - 6664: 3
  - 21: 2
  - 3306: 2
  - 81: 1
  - 1234: 1
- **China**
  - 1433: 42
  - 9092: 6
  - 1723: 5
  - 5003: 5
  - 8009: 2
- **Germany**
  - 2776: 4
  - 8920: 4
  - 57643: 4
  - 9104: 3
  - 2376: 2
- **Netherlands**
  - 9100: 16
  - 17001: 16
  - 80: 13
  - 8728: 7
  - 8180: 4
- **Romania**
  - 22: 2
  - 3355: 2
  - 18518: 2
  - 18549: 2
  - 29097: 2
- **Singapore**
  - 3306: 86
  - 7288: 3
  - 7980: 3
- **South Korea**
  - 5900: 34
  - 13720: 7
- **Switzerland**
  - 5433: 60
  - 5432: 1
- **United Kingdom**
  - 11443: 4
  - 443: 3
  - 13975: 2
  - 15944: 2
  - 24444: 2
- **United States**
  - 11211: 37
  - 27019: 36
  - 15671: 35
  - 28017: 32
  - 31337: 15

**CVEs Exploited:**
- CVE-2006-2369: 56
- CVE-2024-14007 CVE-2024-14007: 5
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 1
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- root: 95
- sa: 41
- user: 5
- admin: 3
- anonymous: 1
- postgres: 1
- root_dev: 1

**Passwords:**
- (empty): 91
- password: 3
- 112233: 2
- 123123: 2
- 123321: 2
- 1234: 2
- 12345678: 2
- 1qaz2wsx: 2
- Xpon@Olt9417#: 2
- qwerty: 2

**OS Distribution:**
- Windows NT kernel: 11915
- Linux 2.2.x-3.x: 11121
- Linux 2.2.x-3.x (barebone): 324
- Windows NT kernel 5.x: 123
- Linux 2.2.x-3.x (no timestamps): 121
- Linux 3.11 and newer: 54
- Mac OS X: 24
- Mac OS X 10.x: 18
- Linux 2.4.x-2.6.x: 4
- FreeBSD: 2

**Hyper-aggressive IPs:**
- 152.42.187.194: 86
- 46.19.137.194: 61
