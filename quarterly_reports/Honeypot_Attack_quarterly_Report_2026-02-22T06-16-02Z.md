
# Honeypot Attack Report - 2026-02-22T06:15:17Z

## Executive Summary:
- **High Attack Volume:** Over 25,000 attacks were recorded in the last 6 hours.
- **Dominant Actor:** The United States was the top attacking country, with over 10,000 attacks. The IP address 144.202.31.88 from the US was hyper-aggressive, accounting for nearly 3,000 attacks alone.
- **ASN Concentration:** A significant portion of attacks originated from DigitalOcean (AS14061) and The Constant Company (AS20473).
- **Common Attack Vectors:** The most frequent alert categories were "Generic Protocol Command Decode" and "Misc activity". The most common alert signature was "SURICATA SSH invalid banner".
- **Credential Stuffing:** The most common username attempted was "root", and the most common password was a blank password.

## Detailed Analysis:

### Total Attacks:
- 25106

### Top Attacking Countries:
- United States: 10255
- India: 3254
- Australia: 2261
- Germany: 1692
- Romania: 1634

### Notable IP Reputations:
- known attacker: 9871
- mass scanner: 774
- bot, crawler: 5
- tor exit node: 5

### Common Alert Categories:
- Generic Protocol Command Decode: 3567
- Misc activity: 2910
- Misc Attack: 2193
- Attempted Information Leak: 440
- Potentially Bad Traffic: 243

### Alert Signatures:
- 2228000 - SURICATA SSH invalid banner: 1376
- 2100560 - GPL INFO VNC server response: 1324
- 2200003 - SURICATA IPv4 truncated packet: 669
- 2200122 - SURICATA AF-PACKET truncated packet: 669
- 2001984 - ET INFO SSH session in progress on Unusual Port: 661

### ASN Information:
- 14061 - DigitalOcean, LLC: 7357
- 20473 - The Constant Company, LLC: 3199
- 47890 - Unmanaged Ltd: 2394
- 396982 - Google LLC: 1331
- 16509 - Amazon.com, Inc.: 1239

### Source IP Addresses:
- 144.202.31.88: 2996
- 178.20.210.32: 1195
- 59.145.41.149: 1110
- 167.71.232.38: 1096
- 209.38.19.117: 1020

### Country to Port Mapping:
- **Australia:**
  - 22: 427
  - 80: 117
- **Germany:**
  - 22: 247
  - 6000: 38
  - 443: 23
- **India:**
  - 445: 1110
  - 22: 381
  - 80: 113
- **Romania:**
  - 22: 283
  - 443: 12
  - 587: 2
- **United States:**
  - 2323: 1449
  - 23: 796
  - 5902: 675

### CVEs Exploited:
- CVE-2024-14007 CVE-2024-14007: 19
- CVE-2025-55182 CVE-2025-55182: 15
- CVE-2021-3449 CVE-2021-3449: 6
- CVE-2019-11500 CVE-2019-11500: 5
- CVE-2023-26801 CVE-2023-26801: 2

### Usernames:
- root: 409
- postgres: 135
- admin: 132
- oracle: 124
- hadoop: 108
- user: 106
- git: 102
- test: 93
- mysql: 57
- ubuntu: 39

### Passwords:
- (blank): 155
- 123456: 108
- 123: 92
- 1234: 85
- 12345678: 72

### OS Distribution:
- Linux 2.2.x-3.x: 38619
- Windows NT kernel: 37020
- Linux 2.2.x-3.x (barebone): 2097
- Windows NT kernel 5.x: 984
- Linux 2.2.x-3.x (no timestamps): 953

### Hyper-aggressive IPs:
- 144.202.31.88: 2996
