# Honeypot Attack Report - 2026-02-22T00:00:22Z

## Executive Summary:
- **High Attack Volume:** A total of 6,895 attacks were observed in the past hour, with the majority originating from the United States and Azerbaijan.
- **Dominant Attacker:** A single IP address, 185.18.245.87, from Azerbaijan, was responsible for 1,828 attacks, indicating a targeted campaign.
- **Common Vulnerabilities:** The most frequently scanned for vulnerability was CVE-2024-14007.
- **Brute Force Attempts:** A significant number of brute force attempts were observed, with "root" being the most common username and "123456" the most common password.
- **Top Alert Signature:** The most common alert signature was "SURICATA SSH invalid banner" (239 occurrences), suggesting a high volume of SSH scanning activity.
- **Operating System Distribution:** The most common operating system identified was Windows NT kernel, with 10,862 instances.

## Detailed Analysis:

**Total Attacks:**
- 6895

**Top Attacking Countries:**
- United States: 2824
- Azerbaijan: 1828
- Germany: 438
- India: 369
- Indonesia: 326

**Notable IP Reputations:**
- known attacker: 1918
- mass scanner: 79
- bot, crawler: 3

**Common Alert Categories:**
- Generic Protocol Command Decode: 519
- Misc activity: 486
- Misc Attack: 282
- Attempted Information Leak: 62
- Web Application Attack: 15

**Alert Signatures:**
- 2228000 - SURICATA SSH invalid banner: 239
- 2100560 - GPL INFO VNC server response: 228
- 2001984 - ET INFO SSH session in progress on Unusual Port: 111
- 2402000 - ET DROP Dshield Block Listed Source group 1: 71
- 2001978 - ET INFO SSH session in progress on Expected Port: 63

**ASN Information:**
- 39232 (Uninet LLC): 1828
- 20473 (The Constant Company, LLC): 1527
- 47890 (Unmanaged Ltd): 449
- 14061 (DigitalOcean, LLC): 444
- 9498 (BHARTI Airtel Ltd.): 369

**Source IP Addresses:**
- 185.18.245.87: 1828
- 144.202.31.88: 1527
- 59.145.41.149: 369
- 178.20.210.32: 340
- 115.124.85.161: 327

**Country to Port Mapping:**
- Azerbaijan
  - 445: 1828
- Germany
  - 22: 68
  - 6000: 38
  - 631: 18
  - 1527: 8
  - 8663: 4
- India
  - 445: 370
  - 8081: 1
- Indonesia
  - 445: 327
- United States
  - 2323: 899
  - 23: 317
  - 2083: 120
  - 5902: 116
  - 5901: 57

**CVEs Exploited:**
- CVE-2024-14007: 3
- CVE-2019-11500: 1

**Usernames:**
- root: 22
- admin: 9
- solana: 9
- dorothy: 8
- sandra: 8
- ubuntu: 8
- ashley: 7
- betty: 7
- carol: 7
- donna: 6

**Passwords:**
- 123456: 20
- 123: 17
- 1234: 17
- 12345678: 12
- solana: 8

**OS Distribution:**
- Linux 2.2.x-3.x: 5786
- Windows NT kernel: 10862
- Linux 2.2.x-3.x (barebone): 360
- Windows NT kernel 5.x: 145
- Linux 3.11 and newer: 36

**Hyper-aggressive IPs:**
- 185.18.245.87: 1828
- 144.202.31.88: 1527
