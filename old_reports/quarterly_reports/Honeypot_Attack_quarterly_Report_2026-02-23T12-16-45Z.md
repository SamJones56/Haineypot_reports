# Honeypot Attack Report - 2026-02-23T12:15:41Z

## Executive Summary:
- **High Attack Volume:** The honeypot network observed a total of 37,376 attacks in the past 6 hours, indicating a significant level of malicious activity.
- **Dominant Attacker:** The United States was the most active attacking country, accounting for 13,834 attacks, followed by Germany and India.
- **ASN Dominance:** DigitalOcean, LLC (AS14061) was the top attacking ASN, responsible for a staggering 26,843 attacks, suggesting a concentration of malicious infrastructure within this provider.
- **Common Attack Vectors:** The most frequent alert category was "Generic Protocol Command Decode", and the most common alert signatures were "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet".
- **Credential Stuffing:** Brute-force attempts were prevalent, with "root" and "admin" being the most targeted usernames and "123456" and "password" as common passwords.
- **Hyper-Aggressive IPs:** Several IP addresses were identified as hyper-aggressive, with five IPs each launching over 1,400 attacks.

## Detailed Analysis:

**Total Attacks:**
- 37,376

**Top Attacking Countries:**
- United States: 13,834
- Germany: 5,271
- India: 4,595
- Canada: 2,513
- United Kingdom: 2,490

**Notable IP Reputations:**
- known attacker: 10,653
- mass scanner: 1,428
- bot, crawler: 8

**Common Alert Categories:**
- Generic Protocol Command Decode: 6,867
- Misc activity: 3,732
- Misc Attack: 2,295
- Attempted Information Leak: 837
- Attempted Administrator Privilege Gain: 210

**Alert Signatures:**
- 2200003, SURICATA IPv4 truncated packet: 2,404
- 2200122, SURICATA AF-PACKET truncated packet: 2,404
- 2100560, GPL INFO VNC server response: 1,314
- 2228000, SURICATA SSH invalid banner: 1,123
- 2038967, ET INFO SSH-2.0-Go version string Observed in Network Traffic: 965

**ASN Information:**
- 14061, DigitalOcean, LLC: 26,843
- 47890, Unmanaged Ltd: 1,997
- 131427, AOHOAVIET: 1,200
- 213412, ONYPHE SAS: 706
- 16509, Amazon.com, Inc.: 590

**Source IP Addresses:**
- 152.42.176.89: 1,667
- 64.227.14.127: 1,610
- 162.243.218.184: 1,498
- 159.65.243.235: 1,443
- 167.71.239.213: 1,438

**Country to Port Mapping:**
- **Canada**
  - 22: 367
  - 8728: 50
  - 8021: 7
  - 5001: 5
  - 10909: 4
- **Germany**
  - 22: 958
  - 80: 49
  - 9092: 33
  - 23: 15
  - 10250: 14
- **India**
  - 22: 894
  - 1574: 8
  - 23: 3
  - 8081: 2
- **United Kingdom**
  - 22: 441
  - 80: 14
  - 4444: 10
  - 443: 8
  - 1550: 8
- **United States**
  - 22: 1,554
  - 5902: 681
  - 5901: 384
  - 5903: 341
  - 8728: 118

**CVEs Exploited:**
- CVE-2025-55182 CVE-2025-55182: 83
- CVE-2024-14007 CVE-2024-14007: 23
- CVE-2021-3449 CVE-2021-3449: 9
- CVE-2019-11500 CVE-2019-11500: 7
- CVE-2006-2369: 2

**Usernames:**
- root: 1,083
- admin: 671
- user: 423
- guest: 317
- test: 312
- oracle: 260
- mysql: 191
- postgres: 186
- ubuntu: 184
- pi: 90

**Passwords:**
- 123456: 332
- 12345678: 203
- 1234: 192
- password: 185
- 123: 174

**OS Distribution:**
- Linux 2.2.x-3.x: 98,516
- Windows NT kernel: 22,140
- Linux 2.2.x-3.x (barebone): 1,416
- Windows NT kernel 5.x: 1,053
- Linux 2.2.x-3.x (no timestamps): 952

**Hyper-aggressive IPs:**
- 152.42.176.89: 1,667
- 64.227.14.127: 1,610
- 162.243.218.184: 1,498
- 159.65.243.235: 1,443
- 167.71.239.213: 1,438
