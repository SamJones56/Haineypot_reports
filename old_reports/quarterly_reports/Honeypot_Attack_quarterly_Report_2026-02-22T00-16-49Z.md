
# Honeypot Attack Report - 2026-02-22T00:15:33Z

## Executive Summary:
- **High Attack Volume:** A total of 25,648 attacks were observed in the past 6 hours, with the majority originating from the United States.
- **Dominant Attacker ASNs:** DigitalOcean, LLC (AS14061) was the most prominent source of attacks, accounting for 4,200 events.
- **Common Vulnerabilities:** A significant number of attacks targeted CVE-2006-2369.
- **Credential Brute-Forcing:** Brute-force attempts were common, with "root" and "admin" as the most frequently used usernames.
- **Hyper-Aggressive IPs:** A small number of IPs were responsible for a large portion of the attacks, with 115.124.85.161 leading at 2,119 attacks.
- **Truncated Packet Signatures:** The most frequent alert signatures were "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet", indicating network anomalies or evasion attempts.

## Detailed Analysis:

### Total Attacks:
25648

### Top Attacking Countries:
- United States: 8465
- Germany: 3339
- India: 2463
- Indonesia: 2120
- Azerbaijan: 1830

### Notable IP Reputations:
- known attacker: 10573
- mass scanner: 534
- bot, crawler: 15
- tor exit node: 13

### Common Alert Categories:
- Generic Protocol Command Decode: 7419
- Misc activity: 3230
- Misc Attack: 1836
- Attempted Information Leak: 380
- Attempted Administrator Privilege Gain: 196
- Web Application Attack: 114
- Potentially Bad Traffic: 80
- Detection of a Network Scan: 21
- access to a potentially vulnerable web application: 13
- A Network Trojan was detected: 12

### Alert Signatures:
- Signature ID: 2200003, Description: SURICATA IPv4 truncated packet, Count: 2412
- Signature ID: 2200122, Description: SURICATA AF-PACKET truncated packet, Count: 2412
- Signature ID: 2100560, Description: GPL INFO VNC server response, Count: 1652
- Signature ID: 2228000, Description: SURICATA SSH invalid banner, Count: 1315
- Signature ID: 2001984, Description: ET INFO SSH session in progress on Unusual Port, Count: 606
- Signature ID: 2221036, Description: SURICATA HTTP Response excessive header repetition, Count: 577
- Signature ID: 2402000, Description: ET DROP Dshield Block Listed Source group 1, Count: 440
- Signature ID: 2001978, Description: ET INFO SSH session in progress on Expected Port, Count: 383
- Signature ID: 2038967, Description: ET INFO SSH-2.0-Go version string Observed in Network Traffic, Count: 334
- Signature ID: 2009582, Description: ET SCAN NMAP -sS window 1024, Count: 268

### ASN Information:
- ASN: 14061, Organization: DigitalOcean, LLC, Count: 4200
- ASN: 47890, Organization: Unmanaged Ltd, Count: 2321
- ASN: 38511, Organization: PT Remala Abadi, Count: 2119
- ASN: 210006, Organization: Shereverov Marat Ahmedovich, Count: 2105
- ASN: 9498, Organization: BHARTI Airtel Ltd., Count: 1983
- ASN: 39232, Organization: Uninet LLC, Count: 1828
- ASN: 20473, Organization: The Constant Company, LLC, Count: 1790
- ASN: 131427, Organization: AOHOAVIET, Count: 1594
- ASN: 202425, Organization: IP Volume inc, Count: 1276
- ASN: 396982, Organization: Google LLC, Count: 1227

### Source IP Addresses:
- 115.124.85.161: 2119
- 178.20.210.32: 2105
- 185.18.245.87: 1828
- 144.202.31.88: 1790
- 103.53.231.159: 1594
- 59.145.41.149: 1110
- 125.20.197.82: 873
- 143.110.164.137: 802
- 129.212.184.194: 689
- 209.38.212.28: 660

### Country to Port Mapping:
- **Azerbaijan**
  - 445: 1828
  - 23: 1
- **Germany**
  - 22: 567
  - 6000: 106
  - 18789: 102
  - 631: 18
  - 5006: 16
- **India**
  - 445: 1983
  - 22: 96
  - 2082: 2
  - 2222: 2
  - 2083: 1
- **Indonesia**
  - 445: 2120
  - 2222: 1
- **United States**
  - 2323: 1027
  - 5902: 699
  - 23: 404
  - 5901: 331
  - 5900: 124

### CVEs Exploited:
- CVE-2006-2369: 148
- CVE-2024-14007 CVE-2024-14007: 21
- CVE-2025-55182 CVE-2025-55182: 13
- CVE-2019-11500 CVE-2019-11500: 7
- CVE-2021-3449 CVE-2021-3449: 7
- CVE-2024-4577 CVE-2002-0953: 4
- CVE-2024-4577 CVE-2024-4577: 4
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 2
- CVE-2021-42013 CVE-2021-42013: 2
- CVE-2023-46604 CVE-2023-46604 CVE-2023-46604: 2

### Usernames:
- root: 204
- admin: 94
- user: 78
- test: 60
- ubuntu: 50
- guest: 41
- sol: 38
- postgres: 25
- oracle: 22
- solana: 21

### Passwords:
- 123456: 156
- 1234: 124
- 123: 121
- 12345678: 118
- password: 41
- 12345: 39
- passw0rd: 25
- 123456789: 23
- admin: 19
- (empty password): 18

### OS Distribution:
- Windows NT kernel: 67079
- Linux 2.2.x-3.x: 56429
- Windows 7 or 8: 5146
- Linux 2.2.x-3.x (barebone): 2379
- Linux 2.2.x-3.x (no timestamps): 2194
- Windows NT kernel 5.x: 799
- Linux 3.11 and newer: 239
- Mac OS X: 94
- Linux 2.4.x-2.6.x: 56
- Linux 3.1-3.10: 7

### Hyper-aggressive IPs:
- 115.124.85.161: 2119
- 178.20.210.32: 2105
- 185.18.245.87: 1828
- 144.202.31.88: 1790
- 103.53.231.159: 1594
- 59.145.41.149: 1110
