# Honeypot Attack Report - 2026-02-23T14:00:29Z

## Executive Summary:
- Over 7,600 attacks were recorded in the past hour.
- The United States was the dominant source of attacks, accounting for over 58% of the total volume.
- A single IP address, 165.245.134.97, was responsible for over 44% of all attacks and is considered a hyper-aggressive actor.
- "GPL INFO VNC server response" was the most frequent alert signature, indicating reconnaissance activity.
- Brute-force attempts were prevalent, with "root" and "123456" being the most commonly used credentials.
- The majority of attacking systems were identified as running Windows NT kernel.

## Detailed Analysis:

**Total Attacks:**
- 7674

**Top Attacking Countries:**
- United States: 4470
- Netherlands: 1081
- Australia: 483
- Germany: 403
- Singapore: 383

**Notable IP Reputations:**
- known attacker: 4513
- mass scanner: 232
- bot, crawler: 1

**Common Alert Categories:**
- Generic Protocol Command Decode: 533
- Misc activity: 523
- Misc Attack: 437
- Attempted Information Leak: 77
- Web Application Attack: 16

**Alert Signatures:**
- ID: 2100560, Signature: GPL INFO VNC server response, Count: 228
- ID: 2228000, Signature: SURICATA SSH invalid banner, Count: 199
- ID: 2402000, Signature: ET DROP Dshield Block Listed Source group 1, Count: 177
- ID: 2001978, Signature: ET INFO SSH session in progress on Expected Port, Count: 122
- ID: 2200003, Signature: SURICATA IPv4 truncated packet, Count: 116

**ASN Information:**
- ASN: 14061, Organization: DigitalOcean, LLC, Count: 6016
- ASN: 47890, Organization: Unmanaged Ltd, Count: 354
- ASN: 131427, Organization: AOHOAVIET, Count: 165
- ASN: 16509, Organization: Amazon.com, Inc., Count: 141
- ASN: 396982, Organization: Google LLC, Count: 128

**Source IP Addresses:**
- 165.245.134.97: 3422
- 164.92.222.100: 612
- 159.223.49.249: 375
- 167.99.253.43: 349
- 167.99.40.47: 320

**Country to Port Mapping:**
- **Australia**
  - 22: 93
- **Germany**
  - 22: 64
  - 4891: 14
  - 49163: 7
- **Netherlands**
  - 22: 205
  - 9100: 16
  - 17001: 8
- **Singapore**
  - 22: 74
  - 11002: 3
  - 5006: 2
- **United States**
  - 22: 692
  - 5902: 113
  - 5901: 58

**CVEs Exploited:**
- CVE-2025-55182 CVE-2025-55182: 15
- CVE-2024-14007 CVE-2024-14007: 2
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2021-3449 CVE-2021-3449: 1

**Usernames:**
- root: 196
- admin: 82
- postgres: 54
- oracle: 46
- test: 41
- user: 30
- backup: 22
- ubuntu: 21
- debian: 19
- daemon: 17

**Passwords:**
- 123456: 227
- 123: 45
- 12345678: 32
- password: 31
- 12345: 29

**OS Distribution:**
- Windows NT kernel: 19119
- Linux 2.2.x-3.x: 15138
- Linux 2.2.x-3.x (barebone): 303
- Windows NT kernel 5.x: 136
- Linux 2.2.x-3.x (no timestamps): 110

**Hyper-aggressive IPs:**
- 165.245.134.97: 3422
