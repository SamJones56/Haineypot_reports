# Honeypot Attack Report - 2026-02-22T03:00:24Z

## Executive Summary:
- **High Attack Volume:** A total of 4,537 attacks were observed in the past hour, with the majority originating from the United States.
- **Dominant Attacker:** The IP address 144.202.31.88, associated with "The Constant Company, LLC", was the most aggressive, accounting for 556 attacks.
- **Common Tactics:** The most frequent attack categories were "Misc activity" and "Generic Protocol Command Decode". The top alert signature was "GPL INFO VNC server response".
- **Credential Stuffing:** Brute-force attempts were prevalent, with common usernames like "oracle" and "test", and simple passwords such as "123456".
- **Exploitation Attempts:** Low numbers of exploitation attempts for CVEs CVE-2024-14007 and CVE-2025-55182 were observed.
- **Operating System Distribution:** The most common operating system identified was "Windows NT kernel".

## Detailed Analysis:

**Total Attacks:**
- 4537

**Top Attacking Countries:**
- United States: 1682
- Australia: 720
- Germany: 495
- India: 397
- Vietnam: 279

**Notable IP Reputations:**
- known attacker: 1949
- mass scanner: 100

**Common Alert Categories:**
- Misc activity: 476
- Generic Protocol Command Decode: 432
- Misc Attack: 360
- Attempted Information Leak: 122
- Attempted Administrator Privilege Gain: 32

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 226
- 2228000 - SURICATA SSH invalid banner: 204
- 2402000 - ET DROP Dshield Block Listed Source group 1: 103
- 2001984 - ET INFO SSH session in progress on Unusual Port: 100
- 2001978 - ET INFO SSH session in progress on Expected Port: 86

**ASN Information:**
- 14061 - DigitalOcean, LLC: 1386
- 20473 - The Constant Company, LLC: 556
- 210006 - Shereverov Marat Ahmedovich: 330
- 47890 - Unmanaged Ltd: 293
- 131427 - AOHOAVIET: 279

**Source IP Addresses:**
- 144.202.31.88: 556
- 167.71.232.38: 393
- 209.38.19.117: 370
- 209.38.23.244: 350
- 178.20.210.32: 330

**Country to Port Mapping:**
- Australia
  - 22: 144
- Germany
  - 22: 68
  - 443: 12
  - 631: 9
- India
  - 22: 77
  - 1244: 2
  - 8087: 2
- United States
  - 2323: 261
  - 23: 148
  - 5902: 114
- Vietnam
  - 22: 56

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2025-55182 CVE-2025-55182: 3
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2021-3449 CVE-2021-3449: 1

**Usernames:**
- oracle: 53
- test: 46
- hadoop: 39
- user: 37
- git: 31
- root: 27
- postgres: 25
- admin: 17
- mysql: 10
- christine: 8

**Passwords:**
- 123456: 24
- 123: 21
- 1234: 17
- 12345678: 13
- 654321: 10

**OS Distribution:**
- Linux 2.2.x-3.x: 5806
- Windows NT kernel: 11371
- Linux 2.2.x-3.x (barebone): 354
- Windows NT kernel 5.x: 174
- Linux 2.2.x-3.x (no timestamps): 96

**Hyper-aggressive IPs:**
- 144.202.31.88: 556
