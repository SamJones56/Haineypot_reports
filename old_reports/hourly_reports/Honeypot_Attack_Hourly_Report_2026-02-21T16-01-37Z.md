# Honeypot Attack Report - 2026-02-21T16:00:17Z

## Executive Summary:
- **High-Volume Attack Activity**: The honeypot network observed a total of 3,056 attacks in the past hour, indicating a significant level of automated scanning and exploitation attempts.
- **Dominant Attacker**: A single IP address, 128.199.198.62, originating from the DigitalOcean ASN, was responsible for 496 attacks, representing over 16% of the total volume, clearly marking it as a hyper-aggressive actor.
- **Geographic Concentration**: The United States was the top attacking country with 860 attacks, followed by Singapore (508) and Germany (414). This suggests a geographically dispersed threat landscape.
- **Common Attack Vectors**: "Generic Protocol Command Decode" (634 attacks) and "Misc activity" (411 attacks) were the most frequent alert categories, pointing towards a prevalence of reconnaissance and protocol-level attacks. The most common alert signature was "GPL INFO VNC server response" with 228 instances.
- **Exploitation and Credential Stuffing**: The report identified attempts to exploit CVE-2024-14007 and CVE-2002-0013/CVE-2002-0012. Additionally, there was a high volume of brute-force attempts using common usernames like "root" and "admin" with simple passwords such as "123" and "123456".
- **Attacker Infrastructure**: The majority of attacks (2,017) originated from IPs with a "known attacker" reputation. The dominant operating systems observed were Linux and Windows NT, which are common for attacker platforms.

## Detailed Analysis:

**Total Attacks:**
- 3056

**Top Attacking Countries:**
- United States: 860
- Singapore: 508
- Germany: 414
- India: 362
- Vietnam: 240

**Notable IP Reputations:**
- known attacker: 2017
- mass scanner: 106
- bot, crawler: 2

**Common Alert Categories:**
- Generic Protocol Command Decode: 634
- Misc activity: 411
- Misc Attack: 317
- Attempted Information Leak: 81
- Potentially Bad Traffic: 32
- Attempted Administrator Privilege Gain: 10
- Potential Corporate Privacy Violation: 4
- Not Suspicious Traffic: 3
- Web Application Attack: 3
- Detection of a Network Scan: 2

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 228
- 2228000 - SURICATA SSH invalid banner: 213
- 2200003 - SURICATA IPv4 truncated packet: 136
- 2200122 - SURICATA AF-PACKET truncated packet: 136
- 2001984 - ET INFO SSH session in progress on Unusual Port: 95
- 2402000 - ET DROP Dshield Block Listed Source group 1: 73
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 43
- 2009582 - ET SCAN NMAP -sS window 1024: 42
- 2001978 - ET INFO SSH session in progress on Expected Port: 41
- 2230002 - SURICATA TLS invalid record type: 30

**ASN Information:**
- 14061 - DigitalOcean, LLC: 615
- 9498 - BHARTI Airtel Ltd.: 362
- 210006 - Shereverov Marat Ahmedovich: 351
- 131427 - AOHOAVIET: 240
- 47890 - Unmanaged Ltd: 226
- 209334 - Modat B.V.: 213
- 202425 - IP Volume inc: 208
- 396982 - Google LLC: 162
- 135377 - UCLOUD INFORMATION TECHNOLOGY HK LIMITED: 62
- 9541 - Cyber Internet Services Pvt Ltd.: 50

**Source IP Addresses:**
- 128.199.198.62: 496
- 59.145.41.149: 362
- 178.20.210.32: 345
- 103.53.231.159: 240
- 129.212.184.194: 113
- 185.242.226.39: 64
- 185.242.226.40: 55
- 185.242.226.46: 54
- 66.167.166.157: 50
- 92.118.39.95: 50

**Country to Port Mapping:**
- **Canada:**
  - 8728: 6
  - 3197: 3
  - 3701: 3
  - 4530: 3
  - 5905: 3
  - 12325: 3
  - 445: 2
  - 1067: 2
  - 1182: 2
  - 1244: 2
- **France:**
  - 443: 8
  - 80: 7
  - 2095: 2
  - 3128: 2
  - 3443: 2
  - 4163: 2
  - 7200: 2
  - 7202: 2
  - 7734: 2
  - 7742: 2
- **Germany:**
  - 22: 69
  - 13783: 8
  - 445: 4
  - 2357: 4
  - 5874: 4
  - 8815: 4
  - 29203: 4
  - 5279: 3
  - 80: 2
  - 443: 2
- **India:**
  - 445: 362
- **Netherlands:**
  - 80: 4
  - 81: 4
  - 3004: 4
  - 6036: 4
  - 6037: 4
  - 20156: 4
  - 22: 2
  - 25: 2
  - 3000: 2
  - 3306: 2
- **Pakistan:**
  - 23: 26
- **Singapore:**
  - 22: 99
  - 2082: 3
  - 4244: 2
  - 80: 1
  - 2002: 1
  - 2375: 1
  - 2376: 1
  - 2377: 1
  - 4243: 1
  - 8265: 1
- **United Kingdom:**
  - 9091: 9
  - 80: 2
  - 1308: 2
  - 1508: 2
  - 2346: 2
  - 7126: 2
  - 7190: 2
  - 8002: 2
  - 8004: 2
  - 22078: 2
- **United States:**
  - 5902: 113
  - 8728: 14
  - 2085: 13
  - 5280: 13
  - 22: 12
  - 8888: 12
  - 1911: 10
  - 6379: 10
  - 9096: 10
  - 9098: 10
- **Vietnam:**
  - 22: 48

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2002-0013 CVE-2002-0012: 1

**Usernames:**
- root: 112
- admin: 11
- postgres: 9
- ubuntu: 9
- john: 8
- robert: 8
- william: 8
- david: 7
- jose: 7
- michael: 7

**Passwords:**
- 123: 17
- 123456: 14
- 1234: 13
- 12345678: 12
- : 2
- 1234567890: 2
- 2025: 2
- Arcanoid_01: 2
- Th3P4ssWord: 2
- admin: 2

**OS Distribution:**
- Linux 2.2.x-3.x: 14555
- Windows NT kernel: 11376
- Linux 2.2.x-3.x (barebone): 386
- Windows 7 or 8: 369
- Linux 2.2.x-3.x (no timestamps): 312
- Windows NT kernel 5.x: 149
- Linux 3.11 and newer: 35
- Linux 2.4.x: 26
- Mac OS X: 24
- FreeBSD: 2

**Hyper-aggressive IPs:**
- 128.199.198.62: 496 attacks
- 59.145.41.149: 362 attacks
- 178.20.210.32: 345 attacks
- 103.53.231.159: 240 attacks
- 129.212.184.194: 113 attacks
- 185.242.226.39: 64 attacks
- 185.242.226.40: 55 attacks
- 185.242.226.46: 54 attacks
- 66.167.166.157: 50 attacks
- 92.118.39.95: 50 attacks
