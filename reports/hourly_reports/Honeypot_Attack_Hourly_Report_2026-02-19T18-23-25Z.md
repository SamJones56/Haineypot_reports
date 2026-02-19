# Honeypot Attack Report - 2026-02-19T18:22:39Z

## Executive Summary:
- The honeypot network observed 585 attacks in the past hour.
- The majority of attacks originated from the United States (198), followed by Germany (91) and Singapore (87).
- The most prominent attacker IP was 4.145.113.4 with 87 attacks, and is a known attacker.
- The most common alert category was "Generic Protocol Command Decode" with 14,823 alerts.
- The most frequent alert signatures were "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet" with 7,390 alerts each.
- The most targeted operating system was Linux 2.2.x-3.x.

## Detailed Analysis:

**Total Attacks:**
- 585

**Top Attacking Countries:**
- United States: 198
- Germany: 91
- Singapore: 87
- United Kingdom: 37
- Netherlands: 31

**Notable IP Reputations:**
- known attacker: 377
- mass scanner: 39

**Common Alert Categories:**
- Generic Protocol Command Decode: 14823
- Misc activity: 543
- Misc Attack: 101
- Attempted Information Leak: 33
- Attempted Administrator Privilege Gain: 1

**Alert Signatures:**
- 2200003, SURICATA IPv4 truncated packet: 7390
- 2200122, SURICATA AF-PACKET truncated packet: 7390
- 2100560, GPL INFO VNC server response: 524
- 2402000, ET DROP Dshield Block Listed Source group 1: 25
- 2023753, ET SCAN MS Terminal Server Traffic on Non-standard Port: 23

**ASN Information:**
- 135377, UCLOUD INFORMATION TECHNOLOGY HK LIMITED: 175
- 8075, Microsoft Corporation: 89
- 14061, DigitalOcean, LLC: 89
- 174, Cogent Communications, LLC: 63
- 396982, Google LLC: 53

**Source IP Addresses:**
- 4.145.113.4: 87
- 104.248.249.212: 30
- 45.148.10.121: 21
- 165.154.164.79: 15
- 207.90.244.25: 15

**Country to Port Mapping:**
- Germany:
  - 50001: 15
  - 20443: 14
  - 60443: 14
  - 22: 8
  - 3444: 4
- Netherlands:
  - 80: 6
  - 17001: 4
  - 22: 3
  - 16831: 3
  - 3001: 2
- Singapore:
  - 5901: 9
  - 5904: 9
  - 5906: 9
  - 5907: 9
  - 5908: 9
- United Kingdom:
  - 30443: 14
  - 9527: 7
  - 7777: 2
  - 8081: 2
  - 28139: 2
- United States:
  - 40443: 10
  - 17000: 8
  - 8081: 7
  - 23: 5
  - 5431: 5

**CVEs Exploited:**
- CVE-2024-14007
- CVE-2025-55182

**Usernames:**
- root: 8
- admin: 1

**Passwords:**
- admin: 4
- 123456: 1
- 123qwe: 1
- Samsung15: 1
- password: 1

**OS Distribution:**
- Linux 2.2.x-3.x: 3929
- Windows NT kernel 5.x: 2093
- Linux 2.2.x-3.x (barebone): 195
- Linux 2.2.x-3.x (no timestamps): 36
- Linux 3.11 and newer: 12

**Hyper-aggressive IPs:**
- 4.145.113.4: 87
