# Honeypot Attack Report - 2026-02-20T23:00:24Z

## Executive Summary:
- A total of 13,368 attacks were observed in the last hour.
- The majority of attacks originated from Paraguay (9,836), with the top attacking IP being 45.175.157.3.
- The most common alert category was "Generic Protocol Command Decode" with 795 instances.
- Top alert signatures include "SURICATA IPv4 truncated packet" (249) and "SURICATA AF-PACKET truncated packet" (249).
- The most common username and password combination was `root` and `1234`.
- The dominant attacking OS was Windows NT kernel.

## Detailed Analysis:

**Total Attacks:**
- 13,368

**Top Attacking Countries:**
- Paraguay: 9,836
- South Africa: 1,089
- United States: 1,016
- Germany: 485
- Latvia: 262

**Notable IP Reputations:**
- known attacker: 1,857
- mass scanner: 125

**Common Alert Categories:**
- Generic Protocol Command Decode: 795
- Misc activity: 425
- Misc Attack: 302
- Potentially Bad Traffic: 70
- Attempted Information Leak: 60

**Alert Signatures:**
- 2200003 - SURICATA IPv4 truncated packet: 249
- 2200122 - SURICATA AF-PACKET truncated packet: 249
- 2100560 - GPL INFO VNC server response: 246
- 2228000 - SURICATA SSH invalid banner: 198
- 2001984 - ET INFO SSH session in progress on Unusual Port: 103

**ASN Information:**
- 267837 - Vicente Sosa Peralta: 9,836
- 327782 - METROFIBRE-NETWORX: 1,089
- 210006 - Shereverov Marat Ahmedovich: 450
- 47890 - Unmanaged Ltd: 265
- 208885 - Noyobzoda Faridduni Saidilhom: 262

**Source IP Addresses:**
- 45.175.157.3: 9,836
- 102.33.155.122: 1,089
- 178.20.210.32: 450
- 86.54.24.29: 262
- 46.19.137.194: 85

**Country to Port Mapping:**
- Germany
  - 22: 91
  - 8920: 4
  - 18085: 4
  - 16344: 2
  - 18099: 2
- Latvia
  - 22: 55
- Paraguay
  - 22: 1,967
- South Africa
  - 445: 1,089
- United States
  - 4369: 33
  - 63406: 31
  - 80: 25
  - 22: 21
  - 8728: 13

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2002-0013 CVE-2002-0012: 1

**Usernames:**
- root: 1,995
- sa: 57
- admin: 23
- ftp: 8
- pi: 8
- sol: 8
- www-data: 8
- supervisor: 6
- sshd: 5
- Admin: 2

**Passwords:**
- 1234: 10
- www-data: 8
- password: 7
- pi: 7
- pfsense: 6

**OS Distribution:**
- Windows NT kernel: 15,825
- Linux 2.2.x-3.x: 5,835
- Linux 2.2.x-3.x (barebone): 335
- Linux 2.2.x-3.x (no timestamps): 292
- Windows NT kernel 5.x: 105

**Hyper-aggressive IPs:**
- 45.175.157.3: 9,836
- 102.33.155.122: 1,089
- 178.20.210.32: 450
- 86.54.24.29: 262
