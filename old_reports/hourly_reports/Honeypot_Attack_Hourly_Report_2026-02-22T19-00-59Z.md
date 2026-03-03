# Honeypot Attack Report - 2026-02-22T19:00:19Z

## Executive Summary:
- **Dominant Actors**: The United States contributed the highest volume of attacks, with DigitalOcean, LLC being the most prominent ASN.
- **High-Volume Signatures**: VNC and SSH-related signatures were the most frequently observed, indicating a focus on remote access services.
- **Credential Stuffing**: Brute-force attempts were prevalent, with common usernames like "root" and "admin" and simple passwords being repeatedly used.
- **Targeted Vulnerabilities**: A small number of CVEs were targeted, suggesting some attackers are attempting to exploit specific known vulnerabilities.

## Detailed Analysis:

**Total Attacks:**
- 3983

**Top Attacking Countries:**
- United States: 1219
- Singapore: 457
- Germany: 432
- Netherlands: 367
- Australia: 339

**Notable IP Reputations:**
- known attacker: 1628
- mass scanner: 67
- bot, crawler: 1

**Common Alert Categories:**
- Misc activity: 530
- Generic Protocol Command Decode: 499
- Misc Attack: 261
- Attempted Information Leak: 58
- Potentially Bad Traffic: 24

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 220
- 2228000 - SURICATA SSH invalid banner: 181
- 2001978 - ET INFO SSH session in progress on Expected Port: 115
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 104
- 2200003 - SURICATA IPv4 truncated packet: 98

**ASN Information:**
- 14061 - DigitalOcean, LLC: 2118
- 47890 - Unmanaged Ltd: 354
- 210006 - Shereverov Marat Ahmedovich: 345
- 202425 - IP Volume inc: 271
- 135377 - UCLOUD INFORMATION TECHNOLOGY HK LIMITED: 131

**Source IP Addresses:**
- 159.223.42.2: 353
- 178.20.210.32: 345
- 170.64.135.166: 254
- 103.53.231.159: 130
- 165.22.236.94: 128

**Country to Port Mapping:**
- Australia:
  - 22: 61
- Germany:
  - 22: 78
  - 2976: 4
  - 8442: 4
  - 9443: 4
  - 9945: 4
- Netherlands:
  - 22: 54
  - 17000: 16
  - 17001: 12
  - 6036: 8
  - 6037: 8
- Singapore:
  - 22: 83
  - 23: 1
  - 3128: 1
  - 5901: 1
  - 5909: 1
- United States:
  - 5902: 114
  - 5903: 56
  - 5901: 54
  - 22: 46
  - 13390: 30

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 6
- CVE-2025-55182 CVE-2025-55182: 2
- CVE-2002-0013 CVE-2002-0012: 1
- CVE-2002-0606: 1
- CVE-2019-11500 CVE-2019-11500: 1

**Usernames:**
- root: 279
- admin: 69
- postgres: 17
- sol: 14
- ubuntu: 12
- user: 12
- ubnt: 10
- test: 9
- redis: 8
- mariadb: 7

**Passwords:**
- 123456: 34
- 1234: 25
- 12345678: 21
- admin: 21
- 12345: 20

**OS Distribution:**
- Linux 2.2.x-3.x: 17870
- Windows NT kernel: 2804
- Linux 2.2.x-3.x (barebone): 358
- Windows NT kernel 5.x: 101
- Linux 2.2.x-3.x (no timestamps): 378

**Hyper-aggressive IPs:**
- 159.223.42.2: 353
- 178.20.210.32: 345
- 170.64.135.166: 254
