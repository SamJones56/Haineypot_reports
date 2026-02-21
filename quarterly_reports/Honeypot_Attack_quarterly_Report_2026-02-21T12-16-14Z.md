# Honeypot Attack Report - 2026-02-21T12:15:28Z

## Executive Summary:
- **High Attack Volume:** Over 22,000 attacks were observed in the last 6 hours, indicating a significant level of malicious activity.
- **Dominant Actor:** A single IP address, 218.21.0.230, originating from China (ASN 4134, Chinanet), was responsible for over 28% of all attacks (6,386 attacks).
- **Geographic Concentration:** Attacks are globally distributed, but highly concentrated from China (6,580 attacks), the United States (4,386 attacks), and India (2,787 attacks).
- **Common Tactics:** The most frequent alert category was "Generic Protocol Command Decode," suggesting a high volume of reconnaissance and protocol-level probing. The most common attack vector from India and Mexico was on port 445 (SMB).
- **Credential Brute Forcing:** The username 'root' was attempted over 1,700 times, indicating widespread brute-force attempts against administrative accounts.
- **Outdated Vulnerabilities:** The most frequently targeted CVE was CVE-2006-2369, a vulnerability from 2006, highlighting that attackers are still scanning for and attempting to exploit legacy systems.

## Detailed Analysis:

**Total Attacks:**
- 22002

**Top Attacking Countries:**
- China: 6580
- United States: 4386
- India: 2787
- Mexico: 1248
- Singapore: 974

**Notable IP Reputations:**
- known attacker: 7793
- mass scanner: 883
- bot, crawler: 4

**Common Alert Categories:**
- Generic Protocol Command Decode: 7955
- Misc activity: 2595
- Misc Attack: 2186
- Attempted Information Leak: 501
- Potentially Bad Traffic: 222

**Alert Signatures:**
- 2200003 - SURICATA IPv4 truncated packet: 2862
- 2200122 - SURICATA AF-PACKET truncated packet: 2862
- 2100560 - GPL INFO VNC server response: 1474
- 2228000 - SURICATA SSH invalid banner: 1296
- 2402000 - ET DROP Dshield Block Listed Source group 1: 640

**ASN Information:**
- 4134 - Chinanet: 6419
- 135806 - Kalpavruksha Communication Services Pvt.ltd: 2741
- 14061 - DigitalOcean, LLC: 1695
- 47890 - Unmanaged Ltd: 1577
- 396982 - Google LLC: 1392

**Source IP Addresses:**
- 218.21.0.230: 6386
- 103.79.11.171: 2741
- 187.251.232.240: 1240
- 128.199.198.62: 814
- 46.19.137.194: 580

**Country to Port Mapping:**
- **China**
  - 22: 1273
  - 1433: 58
  - 23: 14
  - 6379: 12
  - 27017: 8
- **India**
  - 445: 2741
  - 5530: 8
  - 11711: 8
  - 1432: 7
  - 9653: 7
- **Mexico**
  - 445: 1240
  - 23: 1
  - 2022: 1
  - 5555: 1
  - 5901: 1
- **Singapore**
  - 22: 163
  - 3306: 122
  - 7170: 9
  - 2095: 6
  - 9200: 5
- **United States**
  - 5984: 96
  - 8728: 65
  - 5901: 55
  - 445: 53
  - 1080: 53

**CVEs Exploited:**
- CVE-2006-2369: 56
- CVE-2024-14007 CVE-2024-14007: 23
- CVE-2021-3449 CVE-2021-3449: 9
- CVE-2025-55182 CVE-2025-55182: 8
- CVE-2019-11500 CVE-2019-11500: 7

**Usernames:**
- root: 1716
- sa: 57
- guest: 42
- user: 28
- test: 19
- ubuntu: 19
- sol: 18
- admin: 13
- postgres: 13
- solv: 12

**Passwords:**
- : 141
- 123456: 23
- password: 15
- 1234: 14
- 123: 12

**OS Distribution:**
- Linux 2.2.x-3.x: 75740
- Windows NT kernel: 73551
- Linux 2.2.x-3.x (barebone): 1774
- Windows NT kernel 5.x: 951
- Linux 2.2.x-3.x (no timestamps): 950

**Hyper-aggressive IPs:**
- 218.21.0.230: 6386 attacks
- 103.79.11.171: 2741 attacks
- 187.251.232.240: 1240 attacks
