# Honeypot Attack Report - 2026-02-24T00:30:23Z

## Executive Summary:
- **High Attack Volume:** The honeypot network observed a high volume of attacks, with a total of 133,162 incidents in the past 24 hours.
- **Dominant Actor:** The United States was the most active attacking country, responsible for 49,136 attacks, a significant portion of the total volume.
- **ASN Dominance:** DigitalOcean, LLC (AS14061) was the most prominent ASN, with 73,284 attacks originating from its network.
- **Common Vulnerabilities:** The most frequently targeted CVEs were CVE-2025-55182 and CVE-2024-14007, indicating a focus on newer vulnerabilities.
- **Credential Stuffing:** Brute-force attacks using common usernames and passwords like "root", "admin", "123456", and "password" remain a prevalent threat.
- **Hyper-Aggressive IP:** A single IP address, 165.245.134.97, was identified as hyper-aggressive, launching 5,829 attacks.

## Detailed Analysis:

**Total Attacks:**
- 133,162

**Top Attacking Countries:**
- United States: 49,136
- India: 14,910
- Australia: 11,988
- Germany: 10,657
- Vietnam: 6,273

**Notable IP Reputations:**
- known attacker: 50,452
- mass scanner: 4,157
- bot, crawler: 93

**Common Alert Categories:**
- Generic Protocol Command Decode: 27,870
- Misc activity: 12,815
- Misc Attack: 8,496
- Attempted Information Leak: 6,507
- Attempted Administrator Privilege Gain: 430
- Potentially Bad Traffic: 413
- Web Application Attack: 181
- access to a potentially vulnerable web application: 155
- Detection of a Network Scan: 94
- A Network Trojan was detected: 57

**Alert Signatures:**
- 2200003 - SURICATA IPv4 truncated packet: 9,349
- 2200122 - SURICATA AF-PACKET truncated packet: 9,349
- 2100560 - GPL INFO VNC server response: 5,270
- 2228000 - SURICATA SSH invalid banner: 4,546
- 2402000 - ET DROP Dshield Block Listed Source group 1: 2,773
- 2002824 - ET INFO CURL User Agent: 2,387
- 2001978 - ET INFO SSH session in progress on Expected Port: 2,384
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 2,216
- 2001984 - ET INFO SSH session in progress on Unusual Port: 2,083
- 2023753 - ET SCAN MS Terminal Server Traffic on Non-standard Port: 1,610

**ASN Information:**
- 14061 - DigitalOcean, LLC: 73,284
- 47890 - Unmanaged Ltd: 7,273
- 131427 - AOHOAVIET: 4,365
- 18209 - Atria Convergence Technologies Ltd.: 3,157
- 202425 - IP Volume inc: 2,801
- 209334 - Modat B.V.: 2,669
- 9498 - BHARTI Airtel Ltd.: 2,555
- 51167 - Contabo GmbH: 2,504
- 396982 - Google LLC: 2,433
- 211590 - Bucklog SARL: 2,268

**Source IP Addresses:**
- 165.245.134.97: 5,829
- 103.53.231.159: 4,365
- 170.64.230.118: 4,058
- 183.82.0.100: 3,157
- 129.212.184.194: 2,704
- 59.145.41.149: 2,555
- 173.249.27.120: 2,329
- 64.32.31.2: 1,874
- 185.177.72.49: 1,772
- 14.177.96.230: 1,744

**Country to Port Mapping:**
- **Australia:**
  - 22: 2335
  - 2222: 4
  - 23: 1
  - 2202: 1
  - 17000: 1
- **Germany:**
  - 22: 1812
  - 80: 101
  - 4891: 56
  - 1234: 53
  - 10250: 50
- **India:**
  - 445: 5712
  - 22: 1695
  - 23: 107
  - 9200: 60
  - 45737: 56
- **United States:**
  - 22: 4310
  - 5902: 2722
  - 1080: 1874
  - 5901: 1477
  - 5903: 1378
- **Vietnam:**
  - 445: 1748
  - 22: 890
  - 3333: 11
  - 23: 9
  - 7170: 7

**CVEs Exploited:**
- CVE-2025-55182 CVE-2025-55182: 136
- CVE-2024-14007 CVE-2024-14007: 99
- CVE-2021-3449 CVE-2021-3449: 30
- CVE-2002-1149: 29
- CVE-2019-11500 CVE-2019-11500: 25
- CVE-2021-1499 CVE-2021-1499: 17
- CVE-2002-0013 CVE-2002-0012: 8
- CVE-2002-0953: 8
- CVE-2024-4577 CVE-2002-0953: 6
- CVE-2024-4577 CVE-2024-4577: 6

**Usernames:**
- root: 2,981
- admin: 1,631
- user: 885
- test: 720
- oracle: 564
- guest: 542
- ubuntu: 529
- postgres: 514
- mysql: 302
- centos: 275

**Passwords:**
- 123456: 1,443
- 123: 655
- 1234: 595
- 12345678: 576
- password: 483
- 12345: 400
- qwerty: 364
- 123456789: 348
- passw0rd: 280
- 111111: 278

**OS Distribution:**
- Linux 2.2.x-3.x: 354,125
- Windows NT kernel: 299,876
- Windows 7 or 8: 8,732
- Linux 2.2.x-3.x (barebone): 7,023
- Linux 2.2.x-3.x (no timestamps): 6,249
- Linux 3.1-3.10: 4,452
- Windows NT kernel 5.x: 3,948
- Linux 3.11 and newer: 3,649
- Linux 3.x: 1,510
- Mac OS X: 375

**Hyper-aggressive IPs:**
- 165.245.134.97: 5,829
