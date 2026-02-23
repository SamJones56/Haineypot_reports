# Honeypot Attack Report - 2026-02-23T20:00:27Z

## Executive Summary:
- **High Attack Volume:** A total of 4372 attacks were observed in the past hour.
- **Dominant Actors:** Australia (1493 attacks) and the United States (1328 attacks) were the top attacking countries. A single IP address, 170.64.230.118, was responsible for 1493 attacks. The most active ASN was AS14061 (DigitalOcean, LLC) with 2196 attacks.
- **Attack Focus:** The most common alert categories were "Misc activity" (404) and "Generic Protocol Command Decode" (372), with a significant number of scans for MS Terminal Server on non-standard ports (248).
- **Exploitation Attempts:** Several CVEs were detected, with CVE-2024-14007 being the most frequent (6 attempts).
- **Credential Stuffing:** Brute-force attempts were prevalent, with "root" (56) and "admin" (23) as the most common usernames, and "123456" (103) as the most common password.
- **Operating Systems:** The most common attacking operating systems were Windows NT kernel (19488) and Linux 2.2.x-3.x (16215).

## Detailed Analysis:

**Total Attacks:**
- 4372

**Top Attacking Countries:**
- Australia: 1493
- United States: 1328
- Netherlands: 331
- Canada: 250
- Vietnam: 215

**Notable IP Reputations:**
- known attacker: 3654
- mass scanner: 81

**Common Alert Categories:**
- Misc activity: 404
- Generic Protocol Command Decode: 372
- Misc Attack: 314
- Attempted Information Leak: 310
- Potentially Bad Traffic: 13

**Alert Signatures:**
- 2023753 - ET SCAN MS Terminal Server Traffic on Non-standard Port: 248
- 2100560 - GPL INFO VNC server response: 218
- 2228000 - SURICATA SSH invalid banner: 175
- 2001984 - ET INFO SSH session in progress on Unusual Port: 82
- 2402000 - ET DROP Dshield Block Listed Source group 1: 67

**ASN Information:**
- 14061, DigitalOcean, LLC: 2196
- 47890, Unmanaged Ltd: 273
- 396982, Google LLC: 273
- 209334, Modat B.V.: 242
- 131427, AOHOAVIET: 215

**Source IP Addresses:**
- 170.64.230.118: 1493
- 178.128.245.160: 240
- 103.53.231.159: 215
- 46.19.137.194: 166
- 129.212.184.194: 114

**Country to Port Mapping:**
- **Australia**
  - 22: 298
- **Canada**
  - 8728: 4
  - 1422: 2
  - 1998: 2
  - 2454: 2
  - 2986: 2
- **Netherlands**
  - 3388: 80
  - 3390: 80
  - 9999: 80
  - 8000: 20
  - 6037: 16
- **United States**
  - 5902: 114
  - 1344: 79
  - 5903: 58
  - 5901: 54
  - 1293: 39
- **Vietnam**
  - 22: 43

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 6
- CVE-2025-55182 CVE-2025-55182: 2
- CVE-2002-0013 CVE-2002-0012: 1
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2021-3449 CVE-2021-3449: 1

**Usernames:**
- root: 56
- admin: 23
- user: 18
- gast: 8
- gast1: 8
- gast2: 8
- gast3: 8
- hellp: 8
- test: 6
- git: 4

**Passwords:**
- 123456: 103
- 123: 20
- 12345678: 13
- 1234: 12
- 1qaz@WSX: 7

**OS Distribution:**
- Windows NT kernel: 19488
- Linux 2.2.x-3.x: 16215
- Linux 2.2.x-3.x (barebone): 431
- Linux 2.2.x-3.x (no timestamps): 422
- Windows NT kernel 5.x: 170

**Hyper-aggressive IPs:**
- 170.64.230.118: 1493
- 178.128.245.160: 240
- 103.53.231.159: 215
- 46.19.137.194: 166
- 129.212.184.194: 114
