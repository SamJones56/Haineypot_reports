# Honeypot Attack Report - 2026-02-23T06:00:20Z

## Executive Summary:
- **High Attack Volume:** The honeypot network observed a total of 7,598 attacks in the past hour.
- **Dominant Attacker:** A single IP address, 14.177.96.230, originating from Vietnam and associated with VNPT Corp, was responsible for 1,700 attacks, making it a hyper-aggressive actor.
- **Geographic Concentration:** The majority of attacks originated from the United States (2,738), Vietnam (1,920), and India (1,397).
- **Common Attack Vectors:** The most frequent alert signatures were "SURICATA SSH invalid banner" (223 instances) and "GPL INFO VNC server response" (220 instances), indicating a focus on SSH and VNC services.
- **Exploitation Attempts:** There were several attempts to exploit various CVEs, with CVE-2024-14007 being the most frequent.
- **Credential Stuffing:** The most common usernames and passwords attempted were "admin" and "123456" respectively, suggesting widespread credential stuffing attacks.

## Detailed Analysis:

**Total Attacks:**
- 7,598

**Top Attacking Countries:**
- United States: 2,738
- Vietnam: 1,920
- India: 1,397
- Australia: 624
- Canada: 234

**Notable IP Reputations:**
- known attacker: 1,479
- mass scanner: 208
- bot, crawler: 1

**Common Alert Categories:**
- Misc activity: 582
- Generic Protocol Command Decode: 468
- Misc Attack: 364
- Attempted Information Leak: 87
- Potentially Bad Traffic: 35
- Attempted Administrator Privilege Gain: 20
- Web Application Attack: 8
- A Network Trojan was detected: 6
- Detection of a Network Scan: 3
- Attempted User Privilege Gain: 2

**Alert Signatures:**
- 2228000 - SURICATA SSH invalid banner: 223
- 2100560 - GPL INFO VNC server response: 220
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 127
- 2001978 - ET INFO SSH session in progress on Expected Port: 118
- 2402000 - ET DROP Dshield Block Listed Source group 1: 109
- 2001984 - ET INFO SSH session in progress on Unusual Port: 107
- 2200003 - SURICATA IPv4 truncated packet: 49
- 2200122 - SURICATA AF-PACKET truncated packet: 49
- 2009582 - ET SCAN NMAP -sS window 1024: 45
- 2210061 - SURICATA STREAM spurious retransmission: 30

**ASN Information:**
- 14061 - DigitalOcean, LLC: 3,928
- 45899 - VNPT Corp: 1,700
- 47890 - Unmanaged Ltd: 351
- 209334 - Modat B.V.: 221
- 131427 - AOHOAVIET: 210
- 396982 - Google LLC: 138
- 16509 - Amazon.com, Inc.: 123
- 202425 - IP Volume inc: 97
- 213412 - ONYPHE SAS: 96
- 6939 - Hurricane Electric LLC: 64

**Source IP Addresses:**
- 14.177.96.230: 1,700
- 165.227.118.67: 748
- 170.64.152.98: 624
- 157.245.101.183: 550
- 139.59.20.224: 490
- 162.243.7.220: 410
- 192.241.189.141: 350
- 143.244.141.197: 280
- 103.53.231.159: 210
- 129.212.184.194: 114

**Country to Port Mapping:**
- **Australia**
  - 22: 125
- **Canada**
  - 8728: 4
  - 3192: 3
  - 11210: 3
  - 12141: 3
  - 1495: 2
  - 2122: 2
  - 4573: 2
  - 7343: 2
  - 8196: 2
  - 1081: 1
- **China**
  - 1433: 37
  - 4000: 7
  - 9307: 5
  - 25105: 5
  - 27007: 5
  - 12382: 4
  - 22: 3
  - 6379: 3
  - 8888: 3
  - 40005: 3
- **France**
  - 3128: 3
  - 4301: 2
  - 4344: 2
  - 4350: 2
  - 6599: 2
  - 7015: 2
  - 7163: 2
  - 7913: 2
  - 7967: 2
  - 8004: 2
- **Germany**
  - 80: 46
  - 7014: 4
  - 9029: 4
  - 13840: 4
  - 9601: 3
  - 22: 1
  - 8888: 1
- **India**
  - 22: 280
- **Netherlands**
  - 9100: 16
  - 17001: 12
  - 443: 4
  - 17000: 4
  - 22: 3
  - 80: 3
  - 39722: 2
  - 8089: 1
  - 25565: 1
- **Romania**
  - 22: 9
  - 587: 8
  - 2647: 2
  - 7598: 2
  - 9604: 2
  - 9731: 2
  - 19986: 2
  - 21320: 2
  - 22582: 2
  - 23917: 2
- **United States**
  - 22: 320
  - 5902: 116
  - 5903: 57
  - 5901: 54
  - 1143: 39
  - 1180: 39
  - 29092: 34
  - 1962: 33
  - 63406: 31
  - 8728: 28
- **Vietnam**
  - 445: 1,700
  - 22: 44

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2020-10987 CVE-2020-10987: 1
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-2023-26801 CVE-2023-26801: 1
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- admin: 101
- user: 75
- root: 48
- guest: 44
- test: 40
- git: 29
- postgres: 28
- mysql: 27
- hadoop: 26
- zabbix: 26

**Passwords:**
- 123456: 65
- 123: 43
- 1234: 37
- 12345678: 35
- password: 35
- 12345: 26
- 123456789: 23
- passw0rd: 20
- qwerty: 20
- admin: 15

**OS Distribution:**
- Linux 2.2.x-3.x: 13,786
- Windows 7 or 8: 1,758
- Linux 2.2.x-3.x (barebone): 348
- Linux 2.2.x-3.x (no timestamps): 211
- Windows NT kernel 5.x: 209
- Linux 3.11 and newer: 117
- Windows NT kernel: 37
- Mac OS X: 9
- FreeBSD: 2
- Linux 2.4.x: 1

**Hyper-aggressive IPs:**
- 14.177.96.230: 1,700 attacks

**Other Notable Deviations:**
- **High Concentration Patterns:** A single IP from Vietnam (14.177.96.230) was responsible for 100% of the attacks on port 445. This IP alone accounts for over 22% of the total attacks in this period.
- **Signature Spikes:** The "SURICATA SSH invalid banner" and "GPL INFO VNC server response" alerts are significantly higher than other signatures, indicating targeted campaigns against these services.
