# Honeypot Attack Report - 2026-02-23T09:00:21Z

## Executive Summary:
- **High-Volume Attack Activity:** A total of 6,909 attacks were observed in the past hour, with a significant concentration from the United States, which accounted for over a third of the total volume.
- **Dominant Attacker ASN:** DigitalOcean, LLC (AS14061) was the most prominent source of attacks, representing a substantial majority of the observed traffic.
- **Common Attack Vectors:** The most frequent alert category was "Generic Protocol Command Decode," and the top alert signature was related to VNC server responses, indicating a focus on remote access protocols. SSH and truncated packet alerts were also prevalent.
- **Exploitation Attempts:** Several CVEs were targeted, with CVE-2025-55182 being the most frequently exploited vulnerability.
- **Credential Stuffing:** Brute-force attempts were common, with "user," "admin," "guest," and "root" being the most frequently used usernames, and simple numerical sequences like "123456" being the most common passwords.
- **Attacker Infrastructure:** The overwhelming majority of attacking systems were identified as running Linux-based operating systems.

## Detailed Analysis:

**Total Attacks:**
- 6909

**Top Attacking Countries:**
- United States: 2733
- Germany: 920
- India: 889
- Canada: 858
- Singapore: 590

**Notable IP Reputations:**
- known attacker: 2618
- mass scanner: 232
- bot, crawler: 1

**Common Alert Categories:**
- Generic Protocol Command Decode: 659
- Misc activity: 604
- Misc Attack: 426
- Attempted Information Leak: 141
- Attempted Administrator Privilege Gain: 30

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 220
- 2200003 - SURICATA IPv4 truncated packet: 171
- 2200122 - SURICATA AF-PACKET truncated packet: 171
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 162
- 2228000 - SURICATA SSH invalid banner: 161

**ASN Information:**
- 14061, DigitalOcean, LLC: 4811
- 209334, Modat B.V.: 360
- 47890, Unmanaged Ltd: 332
- 131427, AOHOAVIET: 178
- 51852, Private Layer INC: 152

**Source IP Addresses:**
- 64.227.14.127: 660
- 157.245.100.145: 640
- 152.42.176.89: 585
- 162.243.218.184: 550
- 159.65.243.235: 510

**Country to Port Mapping:**
- **United States**
  - 22: 366
  - 5902: 113
  - 5901: 63
- **Germany**
  - 22: 179
  - 7024: 4
  - 8096: 4
- **India**
  - 22: 169
  - 23: 2
- **Canada**
  - 22: 97
  - 8728: 4
  - 1545: 2
- **Singapore**
  - 22: 117
  - 49671: 4
  - 5901: 1

**CVEs Exploited:**
- CVE-2025-55182 CVE-2025-55182: 19
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2019-11500 CVE-2019-11500: 1

**Usernames:**
- user: 173
- admin: 159
- guest: 108
- root: 105
- oracle: 68
- postgres: 59
- test: 55
- pi: 26
- dspace: 25
- ec2-user: 18

**Passwords:**
- 123456: 52
- 12345678: 37
- 1234: 33
- 123: 31
- 654321: 29

**OS Distribution:**
- Linux 2.2.x-3.x: 16999
- Linux 2.2.x-3.x (barebone): 285
- Windows NT kernel 5.x: 184
- Linux 2.2.x-3.x (no timestamps): 154
- Linux 3.11 and newer: 48

**Hyper-aggressive IPs:**
- 64.227.14.127: 660
- 157.245.100.145: 640
- 152.42.176.89: 585
- 162.243.218.184: 550
- 159.65.243.235: 510
