# Honeypot Attack Report - 2026-02-20T03:00:15Z

## Executive Summary:
- **High Attack Volume:** Over 6,000 attacks were observed in the last hour, indicating a significant level of malicious activity.
- **Geographic Concentration:** The majority of attacks originated from India, the United States, and Vietnam, suggesting targeted campaigns or large botnets operating from these regions.
- **Hyper-Aggressive IPs:** Two IP addresses, 103.7.81.84 (India) and 103.237.145.16 (Vietnam), were responsible for over 2,600 attacks combined, demonstrating highly aggressive and persistent threat actors.
- **Common Attack Vectors:** The most frequent alerts were related to "Generic Protocol Command Decode" and "Misc activity", with a high number of "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet" signatures, indicating network scanning and malformed packet injection.
- **Credential Stuffing:** A large number of brute-force attempts were detected, with "root", "admin", and "user" being the most common usernames, and simple passwords like "password" and "123456" being the most common passwords.
- **Dominant Attacker OS:** The vast majority of attacking systems were identified as running Windows NT kernel and Linux 2.2.x-3.x, which are common operating systems for compromised devices used in botnets.

## Detailed Analysis:

**Total Attacks:**
- 6036

**Top Attacking Countries:**
- India: 1869
- United States: 1475
- Vietnam: 1297
- Singapore: 390
- Romania: 170

**Notable IP Reputations:**
- known attacker: 2843
- mass scanner: 211
- tor exit node: 4
- bot, crawler: 2

**Common Alert Categories:**
- Generic Protocol Command Decode: 5158
- Misc activity: 2466
- Misc Attack: 410
- Attempted Information Leak: 62
- Potentially Bad Traffic: 34
- Attempted Administrator Privilege Gain: 4
- Not Suspicious Traffic: 4
- Detection of a Network Scan: 3
- Web Application Attack: 3
- access to a potentially vulnerable web application: 2

**Alert Signatures:**
- 2200003 - SURICATA IPv4 truncated packet: 2498
- 2200122 - SURICATA AF-PACKET truncated packet: 2498
- 2100560 - GPL INFO VNC server response: 2304
- 2402000 - ET DROP Dshield Block Listed Source group 1: 132
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 71
- 2001978 - ET INFO SSH session in progress on Expected Port: 60
- 2221036 - SURICATA HTTP Response excessive header repetition: 52
- 2009582 - ET SCAN NMAP -sS window 1024: 44
- 2210048 - SURICATA STREAM reassembly sequence GAP -- missing packet(s): 23
- 2002752 - ET INFO Reserved Internal IP Traffic: 16

**ASN Information:**
- 45117, Ishans Network: 1344
- 14061, DigitalOcean, LLC: 1324
- 131414, Long Van Soft Solution JSC: 1295
- 8075, Microsoft Corporation: 409
- 396982, Google LLC: 197
- 174, Cogent Communications, LLC: 188
- 47890, Unmanaged Ltd: 170
- 209334, Modat B.V.: 136
- 51852, Private Layer INC: 119
- 213412, ONYPHE SAS: 106

**Source IP Addresses:**
- 103.7.81.84: 1344
- 103.237.145.16: 1295
- 64.227.172.219: 515
- 159.203.105.250: 463
- 4.145.113.4: 389
- 46.19.137.194: 119
- 2.57.122.210: 115
- 2.57.122.96: 55
- 128.241.229.30: 46
- 46.225.120.91: 46

**Country to Port Mapping:**
- India
  - 445: 1344
  - 22: 103
  - 19700: 8
  - 80: 1
  - 9200: 1
- Romania
  - 22: 34
- Singapore
  - 5901: 39
  - 5902: 39
  - 5903: 39
  - 5904: 39
  - 5905: 39
- United States
  - 22: 96
  - 80: 57
  - 5984: 57
  - 8728: 14
  - 9100: 14
- Vietnam
  - 22: 260

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 2
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- root: 281
- admin: 49
- user: 45
- dspace: 13
- elastic: 13
- elasticsearch: 13
- es: 13
- ftptest: 13
- ftpuser: 13
- git: 13

**Passwords:**
- password: 15
- 123456: 14
- 12345: 12
- 12345678: 12
- 123456789: 11
- letmein: 10
- welcome: 10
- admin123: 9
- root123: 9
- (empty): 8

**OS Distribution:**
- Linux 2.2.x-3.x: 8089
- Windows NT kernel: 16738
- Windows NT kernel 5.x: 8837
- Linux 2.2.x-3.x (barebone): 518
- Linux 3.11 and newer: 63
- Linux 2.2.x-3.x (no timestamps): 40
- Mac OS X: 28
- Linux 3.1-3.10: 4
- FreeBSD: 3
- Linux 2.4.x: 2

**Hyper-aggressive IPs:**
- 103.7.81.84: 1344
- 103.237.145.16: 1295
