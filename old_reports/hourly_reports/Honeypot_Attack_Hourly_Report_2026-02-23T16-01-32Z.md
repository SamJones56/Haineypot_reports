# Honeypot Attack Report - 2026-02-23T16:00:25Z

## Executive Summary:
- Over 4,500 attacks were recorded in the past hour, with the majority originating from the United States.
- DigitalOcean, LLC infrastructure was the primary source of attacks, accounting for nearly half of all observed activity.
- The most hyper-aggressive IP, 64.32.31.2, originating from the US and associated with Sharktech, was responsible for 678 attacks alone.
- Dominant attack patterns involved generic protocol command decodes and miscellaneous activity, with a high volume of Suricata alerts for truncated and malformed packets.
- Brute-force activity remains prevalent, with "root" and "admin" as the top targeted usernames and simple numerical sequences as the most common passwords.
- The attacking hosts primarily identified as Windows NT and Linux-based systems.

## Detailed Analysis:

**Total Attacks:**
- 4529

**Top Attacking Countries:**
- United States: 2418
- Canada: 525
- United Kingdom: 368
- Vietnam: 200
- Romania: 156

**Notable IP Reputations:**
- known attacker: 1383
- mass scanner: 176

**Common Alert Categories:**
- Generic Protocol Command Decode: 769
- Misc activity: 490
- Misc Attack: 327
- Attempted Information Leak: 101
- Potentially Bad Traffic: 19

**Alert Signatures:**
- 2200003 - SURICATA IPv4 truncated packet: 217
- 2200122 - SURICATA AF-PACKET truncated packet: 217
- 2100560 - GPL INFO VNC server response: 216
- 2228000 - SURICATA SSH invalid banner: 194
- 2001978 - ET INFO SSH session in progress on Expected Port: 91

**ASN Information:**
- 14061 - DigitalOcean, LLC: 2085
- 46844 - Sharktech: 678
- 47890 - Unmanaged Ltd: 300
- 202425 - IP Volume inc: 212
- 131427 - AOHOAVIET: 190

**Source IP Addresses:**
- 64.32.31.2: 678
- 134.199.206.76: 395
- 159.203.9.12: 378
- 165.22.127.188: 312
- 107.170.33.119: 268

**Country to Port Mapping:**
- **Canada**
  - 22: 74
  - 8728: 8
  - 18097: 3
  - 1409: 2
  - 1982: 2
- **Romania**
  - 22: 21
  - 3026: 2
  - 9527: 2
  - 12576: 2
  - 13537: 2
- **United Kingdom**
  - 22: 59
  - 80: 3
  - 443: 2
  - 10443: 2
  - 11443: 2
- **United States**
  - 1080: 678
  - 22: 131
  - 5902: 112
  - 1235: 78
  - 1250: 78
- **Vietnam**
  - 22: 38
  - 23: 2

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2021-3449 CVE-2021-3449: 1

**Usernames:**
- root: 116
- admin: 67
- ubuntu: 55
- test: 47
- centos: 36
- guest: 26
- user: 22
- postgres: 8
- yptftp: 8
- zabbix: 8

**Passwords:**
- 123456: 29
- 123: 27
- 12345678: 27
- password: 23
- 1234: 22

**OS Distribution:**
- Windows NT kernel: 20033
- Linux 2.2.x-3.x: 16842
- Linux 2.2.x-3.x (no timestamps): 462
- Linux 2.2.x-3.x (barebone): 268
- Windows NT kernel 5.x: 171

**Hyper-aggressive IPs:**
- 64.32.31.2: 678 attacks

**Other Notable Deviations:**
- High concentration of attacks from the United States on port 1080, commonly used for SOCKS proxies, suggests attempts to find and leverage open proxies.
- The ASN DigitalOcean, LLC (14061) is the source of a disproportionately high number of attacks, indicating a potential concentration of malicious actors on this platform.
