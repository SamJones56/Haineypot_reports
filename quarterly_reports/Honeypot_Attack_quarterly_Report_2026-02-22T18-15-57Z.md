
# Honeypot Attack Report - 2026-02-22T18:15:22Z

## Executive Summary:
- Total attacks over the last 6 hours reached 27,641, with the majority of attacks originating from the United States (6,955), Germany (4,028), and the United Kingdom (3,422).
- The most prominent attacker IP was 178.20.210.32 with 1,885 attacks, part of the DigitalOcean, LLC ASN (14061) which was responsible for 8,586 attacks in total.
- A significant portion of source IPs were identified as known attackers (10,403).
- The most frequent alert signature was "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" with 2,458 occurrences.
- Common usernames and passwords used in attacks were 'root' (776) and '123456' (173) respectively.
- The dominant attacking OS was identified as Linux 2.2.x-3.x with 87,139 occurrences.

## Detailed Analysis:

**Total Attacks:**
- 27,641

**Top Attacking Countries:**
- United States: 6,955
- Germany: 4,028
- United Kingdom: 3,422
- Romania: 1,924
- Bolivia: 1,805

**Notable IP Reputations:**
- known attacker: 10,403
- mass scanner: 505
- bot, crawler: 5

**Common Alert Categories:**
- Generic Protocol Command Decode: 5,136
- Misc activity: 2,963
- Attempted Administrator Privilege Gain: 2,500
- Misc Attack: 1,639
- Attempted Information Leak: 594

**Alert Signatures:**
- 2024766 - ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2,458
- 2200003 - SURICATA IPv4 truncated packet: 1,504
- 2200122 - SURICATA AF-PACKET truncated packet: 1,504
- 2100560 - GPL INFO VNC server response: 1,342
- 2228000 - SURICATA SSH invalid banner: 1,202

**ASN Information:**
- 14061 - DigitalOcean, LLC: 8,586
- 47890 - Unmanaged Ltd: 2,465
- 210006 - Shereverov Marat Ahmedovich: 1,892
- 26210 - AXS Bolivia S. A.: 1,805
- 55933 - Cloudie Limited: 1,246

**Source IP Addresses:**
- 178.20.210.32: 1,885
- 200.105.151.2: 1,805
- 45.10.175.246: 1,246
- 59.145.41.149: 1,110
- 197.14.55.168: 819

**Country to Port Mapping:**
- Bolivia:
  - 445: 1805
- Germany:
  - 22: 717
  - 23: 28
  - 8089: 22
  - 30005: 14
  - 445: 13
- Romania:
  - 22: 297
  - 33389: 18
  - 22222: 16
  - 33895: 16
  - 33896: 16
- United Kingdom:
  - 22: 556
  - 4567: 16
  - 80: 14
  - 443: 11
  - 4444: 10
- United States:
  - 5902: 685
  - 5903: 349
  - 5901: 324
  - 51749: 228
  - 22: 159

**CVEs Exploited:**
- CVE-2025-55182 CVE-2025-55182: 33
- CVE-2024-14007 CVE-2024-14007: 14
- CVE-2019-11500 CVE-2019-11500: 9
- CVE-2021-3449 CVE-2021-3449: 9
- CVE-2002-0013 CVE-2002-0012: 5

**Usernames:**
- root: 776
- admin: 274
- user: 122
- oracle: 93
- postgres: 88
- test: 74
- ubuntu: 55
- sol: 45
- mysql: 42
- solana: 33

**Passwords:**
- 123456: 173
- 123: 89
- 1234: 86
- 12345678: 85
- password: 69

**OS Distribution:**
- Linux 2.2.x-3.x: 87139
- Windows NT kernel: 51638
- Linux 2.2.x-3.x (barebone): 1923
- Windows NT kernel 5.x: 661
- Linux 2.2.x-3.x (no timestamps): 1983

**Hyper-aggressive IPs:**
- 178.20.210.32: 1885
- 200.105.151.2: 1805
- 45.10.175.246: 1246
- 59.145.41.149: 1110
