# Honeypot Attack Report - 2026-02-19T21:00:14Z

## Executive Summary:
- The honeypot registered a total of 10,829 attacks in the last hour.
- The majority of attacks originated from Vietnam (6,613), with a single IP address, 103.237.145.16, being responsible for 6,601 of these attacks. This IP is associated with ASN 131414 (Long Van Soft Solution JSC).
- The most common alert category was "Misc activity" (2,494 alerts), with the top signature being "GPL INFO VNC server response" (2,306 alerts).
- Port 22 (SSH) was the most frequently targeted port, particularly from IP addresses in Vietnam.
- Brute force attempts were prevalent, with "root" being the most common username (1,420 attempts).
- The dominant operating system identified for attackers was Linux 2.2.x-3.x.

## Detailed Analysis:

**Total Attacks:**
- 10,829

**Top Attacking Countries:**
- Vietnam: 6,613
- Germany: 1,175
- United States: 1,001
- Australia: 610
- Singapore: 591

**Notable IP Reputations:**
- known attacker: 7,653
- mass scanner: 175

**Common Alert Categories:**
- Misc activity: 2,494
- Generic Protocol Command Decode: 1,280
- Misc Attack: 390
- Attempted Information Leak: 70
- Potentially Bad Traffic: 31

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 2,306
- 2200003 - SURICATA IPv4 truncated packet: 572
- 2200122 - SURICATA AF-PACKET truncated packet: 572
- 2402000 - ET DROP Dshield Block Listed Source group 1: 117
- 2001978 - ET INFO SSH session in progress on Expected Port: 93

**ASN Information:**
- 131414, Long Van Soft Solution JSC: 6,601
- 14061, DigitalOcean, LLC: 2,584
- 8075, Microsoft Corporation: 421
- 396982, Google LLC: 195
- 174, Cogent Communications, LLC: 129

**Source IP Addresses:**
- 103.237.145.16: 6,601
- 165.227.161.214: 430
- 4.145.113.4: 385
- 104.248.249.212: 345
- 207.154.239.37: 340

**Country to Port Mapping:**
- Australia:
  - 22: 122
- Germany:
  - 22: 224
  - 1723: 13
  - 7443: 4
- Singapore:
  - 5904: 39
  - 5906: 39
  - 5907: 39
- United States:
  - 22: 45
  - 15671: 35
  - 8728: 21
- Vietnam:
  - 22: 1,321
  - 8899: 7
  - 2222: 1

**CVEs Exploited:**
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2002-0013 CVE-2002-0012: 1
- CVE-2024-14007 CVE-2024-14007: 1
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- root: 1,420
- mysql: 32
- admin: 30
- oracle: 30
- postgres: 27
- odoo: 25
- nagios: 19
- docker: 16
- sa: 16
- guest: 14

**Passwords:**
- password: 32
- 123456: 30
- qwerty: 30
- 12345678: 20
- 12345: 19

**OS Distribution:**
- Linux 2.2.x-3.x: 16,130
- Windows NT kernel 5.x: 9,201
- Linux 2.2.x-3.x (barebone): 467
- Linux 3.11 and newer: 43
- Linux 2.2.x-3.x (no timestamps): 70

**Hyper-aggressive IPs:**
- 103.237.145.16: 6,601 attacks