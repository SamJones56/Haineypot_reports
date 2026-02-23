# Honeypot Attack Report - 2026-02-23T10:00:27Z

## Executive Summary:
- **High Attack Volume**: A total of 6,438 attacks were observed in the past hour, indicating a significant level of malicious activity.
- **Dominant Attacker Origin**: The United States was the most prominent source of attacks, accounting for 2,472 incidents, followed by Germany (797) and India (750).
- **ASN Concentration**: A large portion of attacks (4,921) originated from a single ASN, AS14061 (DigitalOcean, LLC), suggesting a coordinated campaign or a compromised network segment.
- **Common Attack Vectors**: The most frequent alert categories were "Misc activity" (611) and "Generic Protocol Command Decode" (569), with "GPL INFO VNC server response" being the top alert signature.
- **Credential Brute-Forcing**: A high number of login attempts were observed using common usernames such as "mysql", "test", and "root", paired with weak passwords like "123456".
- **Exploitation Activity**: Several CVEs were targeted, with CVE-2025-55182 being the most frequently exploited.

## Detailed Analysis:

**Total Attacks:**
- 6438

**Top Attacking Countries:**
- United States: 2472
- Germany: 797
- India: 750
- Canada: 721
- Singapore: 677

**Notable IP Reputations:**
- known attacker: 1940
- mass scanner: 243
- bot, crawler: 3

**Common Alert Categories:**
- Misc activity: 611
- Generic Protocol Command Decode: 569
- Misc Attack: 366
- Attempted Information Leak: 177
- Attempted Administrator Privilege Gain: 42

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 216
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 163
- 2001978 - ET INFO SSH session in progress on Expected Port: 150
- 2228000 - SURICATA SSH invalid banner: 145
- 2200003 - SURICATA IPv4 truncated packet: 139

**ASN Information:**
- 14061 - DigitalOcean, LLC: 4921
- 47890 - Unmanaged Ltd: 210
- 131427 - AOHOAVIET: 200
- 213412 - ONYPHE SAS: 133
- 135377 - UCLOUD INFORMATION TECHNOLOGY HK LIMITED: 99

**Source IP Addresses:**
- 152.42.176.89: 615
- 162.243.218.184: 555
- 159.65.243.235: 525
- 64.227.14.127: 515
- 178.128.236.77: 510

**Country to Port Mapping:**
- **Canada**
  - 22: 132
  - 8728: 10
  - 1186: 1
  - 1955: 1
  - 2387: 1
- **Germany**
  - 22: 139
  - 80: 46
  - 9305: 7
  - 7024: 4
  - 9681: 4
- **India**
  - 22: 146
- **Singapore**
  - 22: 130
  - 443: 2
  - 80: 1
  - 5901: 1
  - 5909: 1
- **United States**
  - 22: 328
  - 5902: 113
  - 5903: 57
  - 5901: 56
  - 8728: 28

**CVEs Exploited:**
- CVE-2025-55182 CVE-2025-55182: 13
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2021-3449 CVE-2021-3449: 1

**Usernames:**
- mysql: 117
- test: 114
- root: 106
- oracle: 101
- es: 49
- guest: 49
- ftp: 47
- nginx: 36
- git: 28
- newuser: 24

**Passwords:**
- 123456: 58
- 12345678: 43
- 1234: 34
- P@ssw0rd: 33
- password: 33

**OS Distribution:**
- Linux 2.2.x-3.x: 16942
- Windows NT kernel 5.x: 228
- Linux 2.2.x-3.x (barebone): 194
- Linux 2.2.x-3.x (no timestamps): 101
- Linux 3.11 and newer: 30

**Hyper-aggressive IPs:**
- 152.42.176.89: 615
- 162.243.218.184: 555
- 159.65.243.235: 525
- 64.227.14.127: 515
- 178.128.236.77: 510
