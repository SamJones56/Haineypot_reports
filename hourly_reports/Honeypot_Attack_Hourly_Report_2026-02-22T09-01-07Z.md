# Honeypot Attack Report - 2026-02-22T09:00:15Z

## Executive Summary:
- **High Attack Volume:** The honeypot network observed a total of 3,025 attacks in the past hour, indicating a significant level of malicious activity.
- **Dominant Attacker:** The United States was the most prominent source of attacks, accounting for 1,550 of the total, which is more than half of all observed attacks.
- **Hyper-Aggressive IPs:** Two IP addresses, 165.22.2.4 and 165.22.26.70, were identified as hyper-aggressive, launching 444 and 430 attacks respectively.
- **Common Vulnerabilities:** The most frequently targeted vulnerabilities were CVE-2023-46604 and CVE-2024-14007, suggesting a focus on recently disclosed security flaws.
- **Credential Stuffing:** A high volume of common usernames and passwords such as "admin," "user," "root," and "123456" were used in brute-force attempts.
- **Linux-Based Attacks:** The overwhelming majority of attacks originated from systems running the Linux operating system, with "Linux 2.2.x-3.x" being the most common variant.

## Detailed Analysis:

**Total Attacks:**
- 3025

**Top Attacking Countries:**
- United States: 1550
- Germany: 481
- Canada: 148
- Netherlands: 140
- Romania: 79

**Notable IP Reputations:**
- known attacker: 1239
- mass scanner: 147

**Common Alert Categories:**
- Generic Protocol Command Decode: 581
- Misc activity: 452
- Misc Attack: 399
- Attempted Information Leak: 51
- Potentially Bad Traffic: 18

**Alert Signatures:**
- 2228000, SURICATA SSH invalid banner: 246
- 2100560, GPL INFO VNC server response: 234
- 2402000, ET DROP Dshield Block Listed Source group 1: 122
- 2001984, ET INFO SSH session in progress on Unusual Port: 109
- 2200003, SURICATA IPv4 truncated packet: 87

**ASN Information:**
- 14061, DigitalOcean, LLC: 1169
- 396982, Google LLC: 272
- 47890, Unmanaged Ltd: 198
- 16509, Amazon.com, Inc.: 179
- 209334, Modat B.V.: 136

**Source IP Addresses:**
- 165.22.2.4: 444
- 165.22.26.70: 430
- 129.212.184.194: 114
- 34.158.168.101: 95
- 144.202.31.88: 63

**Country to Port Mapping:**
- **Canada:**
  - 8880: 5
  - 8728: 4
  - 52230: 3
  - 1125: 2
  - 1529: 2
- **Germany:**
  - 22: 86
  - 7800: 4
  - 8231: 4
  - 9300: 4
  - 9945: 4
- **Netherlands:**
  - 443: 95
  - 9100: 16
  - 17001: 8
  - 8728: 7
  - 80: 3
- **Romania:**
  - 22: 7
  - 1821: 2
  - 6049: 2
  - 8328: 2
  - 15489: 2
- **United States:**
  - 5902: 118
  - 22: 85
  - 5901: 59
  - 3391: 57
  - 5903: 57

**CVEs Exploited:**
- CVE-2023-46604 CVE-2023-46604 CVE-2023-46604: 2
- CVE-2024-14007 CVE-2024-14007: 2
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2021-3449 CVE-2021-3449: 1

**Usernames:**
- admin: 59
- user: 38
- root: 17
- postgres: 15
- hadoop: 13
- mysql: 13
- oracle: 13
- test: 13
- zabbix: 13
- git: 8

**Passwords:**
- 123456: 11
- 1234: 10
- 12345: 10
- 123: 9
- 12345678: 9

**OS Distribution:**
- Linux 2.2.x-3.x: 11425
- Linux 2.2.x-3.x (barebone): 333
- Windows NT kernel 5.x: 172
- Linux 2.2.x-3.x (no timestamps): 132
- Linux 3.11 and newer: 39

**Hyper-aggressive IPs:**
- 165.22.2.4: 444
- 165.22.26.70: 430
- 129.212.184.194: 114
