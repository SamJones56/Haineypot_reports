# Honeypot Attack Report - 2026-02-23T11:00:26Z

## Executive Summary:
- Over 6,400 attacks were observed in the past hour, with the majority originating from the United States, United Kingdom, and Germany.
- A significant portion of the attacks (over 70%) originated from AS14061 (DigitalOcean, LLC).
- The most common alert category was "Misc activity", and the most frequent alert signature was "GPL INFO VNC server response".
- Attackers were observed attempting to exploit CVE-2025-55182 and using common usernames and passwords such as "root" and "123456".
- The dominant attacking operating system was Linux 2.2.x-3.x.
- Five IP addresses were identified as hyper-aggressive, each with over 480 attacks.

## Detailed Analysis:

**Total Attacks:**
- 6418

**Top Attacking Countries:**
- United States: 1862
- United Kingdom: 1067
- Germany: 1045
- India: 821
- Netherlands: 599

**Notable IP Reputations:**
- known attacker: 1594
- mass scanner: 249

**Common Alert Categories:**
- Misc activity: 660
- Generic Protocol Command Decode: 609
- Misc Attack: 419
- Attempted Information Leak: 143
- Attempted Administrator Privilege Gain: 41

**Alert Signatures:**
- ID: 2100560, Signature: GPL INFO VNC server response, Count: 228
- ID: 2228000, Signature: SURICATA SSH invalid banner, Count: 196
- ID: 2001978, Signature: ET INFO SSH session in progress on Expected Port, Count: 168
- ID: 2038967, Signature: ET INFO SSH-2.0-Go version string Observed in Network Traffic, Count: 168
- ID: 2402000, Signature: ET DROP Dshield Block Listed Source group 1, Count: 158

**ASN Information:**
- ASN: 14061, Organization: DigitalOcean, LLC, Count: 4678
- ASN: 47890, Organization: Unmanaged Ltd, Count: 368
- ASN: 131427, Organization: AOHOAVIET, Count: 210
- ASN: 16509, Organization: Amazon.com, Inc., Count: 133
- ASN: 213412, Organization: ONYPHE SAS, Count: 113

**Source IP Addresses:**
- 167.71.140.87: 532
- 143.110.164.56: 519
- 157.245.104.161: 498
- 188.166.48.57: 495
- 64.227.125.176: 485

**Country to Port Mapping:**
- Germany
  - 22: 182
  - 9092: 33
  - 5666: 7
  - 6150: 4
  - 8453: 4
- India
  - 22: 159
  - 8081: 2
- Netherlands
  - 22: 98
  - 9100: 16
  - 8728: 14
  - 3478: 8
  - 6036: 8
- United Kingdom
  - 22: 201
  - 443: 2
  - 6999: 1
  - 7860: 1
  - 13839: 1
- United States
  - 22: 160
  - 1221: 117
  - 5902: 114
  - 5903: 57
  - 5901: 55

**CVEs Exploited:**
- CVE-2025-55182 CVE-2025-55182: 18
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2006-2369: 2
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2019-11500 CVE-2019-11500: 1

**Usernames:**
- root: 301
- admin: 185
- user: 77
- test: 73
- ubuntu: 48
- postgres: 30
- centos: 20
- mysql: 18
- oracle: 16
- guest: 10

**Passwords:**
- 123456: 60
- password: 34
- 1234: 32
- 12345678: 31
- admin: 30

**OS Distribution:**
- Linux 2.2.x-3.x: 16784
- Linux 2.2.x-3.x (barebone): 227
- Windows NT kernel 5.x: 117
- Linux 2.2.x-3.x (no timestamps): 233
- Linux 3.11 and newer: 61

**Hyper-aggressive IPs:**
- 167.71.140.87: 532
- 143.110.164.56: 519
- 157.245.104.161: 498
- 188.166.48.57: 495
- 64.227.125.176: 485
