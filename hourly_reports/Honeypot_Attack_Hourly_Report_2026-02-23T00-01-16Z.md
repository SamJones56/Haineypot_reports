# Honeypot Attack Report - 2026-02-23T00:00:22Z

## Executive Summary:
- **High Volume of Attacks:** A total of 10,290 attacks were observed in the past hour, indicating a significant level of malicious activity.
- **Geographic Concentration:** Australia was the dominant source of attacks, accounting for 6,531 incidents, followed by the United States with 1,423.
- **ASN Dominance:** DigitalOcean, LLC (AS14061) was the most prominent source ASN, with 8,186 attacks originating from its network. This suggests a potential concentration of compromised or malicious actors within this provider.
- **Common Attack Vectors:** The most frequent alert signatures were related to VNC and SSH, with "GPL INFO VNC server response" and "SURICATA SSH invalid banner" being the most common.
- **Credential Brute-Forcing:** A high number of authentication attempts were observed, with "admin" and "root" as the most targeted usernames and "123456" as the most common password.
- **Hyper-Aggressive IPs:** Three IP addresses were identified as hyper-aggressive, launching thousands of attacks: 209.38.80.88, 209.38.29.178, and 170.64.162.36.

## Detailed Analysis:

**Total Attacks:**
- 10,290

**Top Attacking Countries:**
- Australia: 6,531
- United States: 1,423
- Singapore: 538
- India: 400
- Germany: 345

**Notable IP Reputations:**
- known attacker: 1,674
- mass scanner: 85
- bot, crawler: 5

**Common Alert Categories:**
- Misc activity: 491
- Generic Protocol Command Decode: 402
- Misc Attack: 242
- Attempted Information Leak: 81
- Potentially Bad Traffic: 22

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 224
- 2228000 - SURICATA SSH invalid banner: 149
- 2001978 - ET INFO SSH session in progress on Expected Port: 114
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 74
- 2001984 - ET INFO SSH session in progress on Unusual Port: 70

**ASN Information:**
- 14061 - DigitalOcean, LLC: 8,186
- 210006 - Shereverov Marat Ahmedovich: 319
- 47890 - Unmanaged Ltd: 250
- 131427 - AOHOAVIET: 220
- 396982 - Google LLC: 217

**Source IP Addresses:**
- 209.38.80.88: 2,454
- 209.38.29.178: 2,223
- 170.64.162.36: 1,484
- 165.245.191.137: 479
- 165.245.139.61: 460

**Country to Port Mapping:**
- **Australia**
  - 22: 1304
- **Germany**
  - 22: 65
  - 1028: 8
  - 9028: 4
  - 8158: 3
  - 5552: 2
- **India**
  - 22: 80
- **Singapore**
  - 22: 104
  - 6379: 6
  - 9049: 3
  - 23: 1
  - 5901: 1
- **United States**
  - 5902: 116
  - 22: 96
  - 5903: 58
  - 5901: 56
  - 1027: 39

**CVEs Exploited:**
- CVE-2025-55182 CVE-2025-55182: 12
- CVE-2024-14007 CVE-2024-14007: 5
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2021-3449 CVE-2021-3449: 2

**Usernames:**
- admin: 166
- root: 137
- git: 68
- test: 46
- hadoop: 40
- administrator: 33
- oracle: 29
- postgres: 29
- mysql: 28
- ubuntu: 23

**Passwords:**
- 123456: 335
- 123: 57
- password: 40
- 111111: 29
- 12345678: 29

**OS Distribution:**
- Linux 2.2.x-3.x: 11201
- Windows NT kernel: 2306
- Linux 2.2.x-3.x (barebone): 305
- Windows NT kernel 5.x: 157
- Linux 2.2.x-3.x (no timestamps): 336

**Hyper-aggressive IPs:**
- 209.38.80.88: 2454
- 209.38.29.178: 2223
- 170.64.162.36: 1484
