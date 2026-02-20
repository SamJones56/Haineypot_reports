# Honeypot Attack Report - 2026-02-20T00:15:18Z

**Executive Summary:**
- Over 48,000 attacks were recorded in the last 6 hours, with a significant concentration from a single IP address.
- The majority of attacks originated from Vietnam, accounting for more than half of all observed activity.
- The most prolific attacker was identified as IP 103.237.145.16, associated with ASN 131414 (Long Van Soft Solution JSC), responsible for over 24,500 attacks.
- A large number of attacks were categorized as "Misc activity," with the "GPL INFO VNC server response" signature being the most frequent.
- Credential stuffing attempts were common, with "root" being the most targeted username and "password" being the most common password.
- The attacking systems were predominantly identified as Linux-based operating systems.

**Detailed Analysis:**

**Total Attacks:**
- 48,418

**Top Attacking Countries:**
- Vietnam: 24,567
- United States: 6,462
- Germany: 5,558
- Singapore: 3,277
- India: 1,933

**Notable IP Reputations:**
- known attacker: 32,713
- mass scanner: 1,101
- tor exit node: 6
- bot, crawler: 2

**Common Alert Categories:**
- Misc activity: 14,855
- Generic Protocol Command Decode: 4,891
- Misc Attack: 2,401
- Attempted Information Leak: 453
- Potentially Bad Traffic: 218

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 13,872
- 2200003 - SURICATA IPv4 truncated packet: 1,920
- 2200122 - SURICATA AF-PACKET truncated packet: 1,920
- 2402000 - ET DROP Dshield Block Listed Source group 1: 745
- 2001978 - ET INFO SSH session in progress on Expected Port: 452

**ASN Information:**
- 131414 (Long Van Soft Solution JSC): 24,507
- 14061 (DigitalOcean, LLC): 12,451
- 8075 (Microsoft Corporation): 2,477
- 396982 (Google LLC): 1,440
- 174 (Cogent Communications, LLC): 1,104

**Source IP Addresses:**
- 103.237.145.16: 24,507
- 4.145.113.4: 2,308
- 139.59.82.171: 1,543
- 207.154.239.37: 1,503
- 104.248.249.212: 1,275

**Country to Port Mapping:**
- **Germany**
  - 22: 1049
  - 1723: 47
  - 50001: 16
  - 9443: 14
  - 20443: 14
- **India**
  - 22: 364
  - 8728: 35
  - 8085: 16
  - 30005: 14
  - 25: 6
- **Singapore**
  - 5901: 231
  - 5902: 231
  - 5904: 231
  - 5906: 231
  - 5907: 231
- **United States**
  - 22: 165
  - 8728: 64
  - 80: 47
  - 3399: 44
  - 15671: 35
- **Vietnam**
  - 22: 4908
  - 2379: 28
  - 8899: 7
  - 2222: 1

**CVEs Exploited:**
- CVE-2024-14007
- CVE-2025-55182
- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013, CVE-2002-0012

**Usernames:**
- root: 5,236
- admin: 153
- sa: 91
- backup: 84
- mysql: 80
- guest: 79
- postgres: 77
- debian: 75
- docker: 75
- git: 74

**Passwords:**
- password: 172
- 123456: 168
- qwerty: 126
- 12345: 123
- 12345678: 119

**OS Distribution:**
- Linux 2.2.x-3.x: 81,858
- Windows NT kernel 5.x: 56,713
- Linux 2.2.x-3.x (barebone): 3,213
- Linux 2.2.x-3.x (no timestamps): 353
- Linux 3.11 and newer: 303

**Hyper-aggressive IPs:**
- 103.237.145.16: 24,507 attacks
