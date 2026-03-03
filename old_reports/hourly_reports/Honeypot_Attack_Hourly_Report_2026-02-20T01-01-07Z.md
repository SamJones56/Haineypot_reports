# Honeypot Attack Report - 2026-02-20T01:00:11Z

## Executive Summary:
- **High Attack Volume:** A total of 9,836 attacks were observed in the past hour.
- **Dominant Attacker:** A single IP address, 103.237.145.16, originating from Vietnam and associated with "Long Van Soft Solution JSC" (ASN 131414), was responsible for the vast majority of attacks (6,486). This IP is classified as a "known attacker".
- **Geographic Concentration:** Vietnam was the top attacking country with 6,486 attacks, followed by the United States (942) and Singapore (694).
- **Common Attack Vectors:** The most frequent alert signature was "GPL INFO VNC server response" (2,290 instances), and the most common alert category was "Misc activity" (2,412 instances).
- **Credential Stuffing:** Brute-force attempts were prevalent, with "root" being the most commonly used username (1,320 attempts). Common passwords such as "123456", "password", and variations were also observed.
- **Operating System Distribution:** The most common operating systems identified were Windows NT kernel 5.x (8,932) and Linux 2.2.x-3.x (7,857).

## Detailed Analysis:

**Total Attacks:**
- 9,836

**Top Attacking Countries:**
- Vietnam: 6,486
- United States: 942
- Singapore: 694
- Germany: 435
- Switzerland: 229

**Notable IP Reputations:**
- known attacker: 7,935
- mass scanner: 223

**Common Alert Categories:**
- Misc activity: 2,412
- Generic Protocol Command Decode: 561
- Misc Attack: 361
- Attempted Information Leak: 51
- Potentially Bad Traffic: 47
- Attempted Administrator Privilege Gain: 15
- Web Application Attack: 8
- A Network Trojan was detected: 6
- access to a potentially vulnerable web application: 3
- Attempted User Privilege Gain: 2

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 2,290
- 2200003 - SURICATA IPv4 truncated packet: 192
- 2200122 - SURICATA AF-PACKET truncated packet: 192
- 2402000 - ET DROP Dshield Block Listed Source group 1: 123
- 2001978 - ET INFO SSH session in progress on Expected Port: 64
- 2210048 - SURICATA STREAM reassembly sequence GAP -- missing packet(s): 53
- 2009582 - ET SCAN NMAP -sS window 1024: 39
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 35
- 2010935 - ET SCAN Suspicious inbound to MSSQL port 1433: 33
- 2260002 - SURICATA Applayer Detect protocol only one direction: 21

**ASN Information:**
- 131414 - Long Van Soft Solution JSC: 6,486
- 14061 - DigitalOcean, LLC: 1,010
- 8075 - Microsoft Corporation: 409
- 396982 - Google LLC: 235
- 51852 - Private Layer INC: 229
- 202425 - IP Volume inc: 226
- 174 - Cogent Communications, LLC: 145
- 47890 - Unmanaged Ltd: 145
- 213412 - ONYPHE SAS: 130
- 135377 - UCLOUD INFORMATION TECHNOLOGY HK LIMITED: 123

**Source IP Addresses:**
- 103.237.145.16: 6,486
- 4.145.113.4: 387
- 207.154.211.38: 381
- 152.42.206.51: 300
- 46.19.137.194: 229
- 139.59.82.171: 200
- 185.242.226.40: 97
- 2.57.122.208: 75
- 101.36.108.158: 72
- 2.57.122.96: 70

**Country to Port Mapping:**
- **Germany:**
  - 22: 75
  - 7402: 7
  - 6141: 4
  - 8836: 4
  - 39153: 4
- **Singapore:**
  - 22: 60
  - 5901: 39
  - 5904: 39
  - 5906: 39
  - 5907: 39
- **Switzerland:**
  - 5434: 228
  - 5432: 1
- **United States:**
  - 27018: 38
  - 443: 21
  - 1443: 14
  - 5038: 13
  - 13563: 11
- **Vietnam:**
  - 22: 1298

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2003-0825: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2025-55182 CVE-2025-55182: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1

**Usernames:**
- root: 1320
- sa: 29
- dspace: 22
- postgres: 14
- docker: 13
- elastic: 13
- mysql: 13
- odoo: 13
- oracle: 13
- developer: 11

**Passwords:**
- 123456: 20
- 12345678: 16
- 12345: 15
- 1234567: 15
- 123456789: 15
- password: 15
- P@ssw0rd123: 11
- admin123: 11
- root123: 11
- abc123: 10

**OS Distribution:**
- Windows NT kernel 5.x: 8932
- Linux 2.2.x-3.x: 7857
- Windows NT kernel: 515
- Linux 2.2.x-3.x (barebone): 479
- Linux 3.11 and newer: 37
- Linux 2.2.x-3.x (no timestamps): 26
- Linux 3.1-3.10: 20
- Mac OS X: 11
- Windows 7 or 8: 2

**Hyper-aggressive IPs:**
- 103.237.145.16: 6,486 attacks
