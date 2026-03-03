# Honeypot Attack Report - 2026-02-21T10:00:12Z

## Executive Summary:
- **High Volume of Attacks:** A total of 6,640 attacks were observed in the past hour, indicating a significant level of malicious activity.
- **Dominant Attacker:** A single IP address, 218.21.0.230, originating from China (ASN 4134, Chinanet), was responsible for a substantial portion of the attacks, with 3,886 documented events. This IP is considered a hyper-aggressive actor.
- **Geographic Concentration:** The majority of attacks originated from China (3,899), followed by Mexico (1,245) and the United States (782).
- **Targeted Ports:** Port 445 (SMB) was the most targeted port, primarily from Mexico, while port 22 (SSH) was heavily targeted from China.
- **Credential Brute-Forcing:** The most commonly attempted username was "root" with 803 attempts, indicating a focus on brute-force attacks against privileged accounts.
- **Known Attacker Activity:** A significant number of attacks (1,191) were attributed to IPs with a reputation as "known attackers," suggesting activity from established malicious actors.

## Detailed Analysis:

**Total Attacks:**
- 6,640

**Top Attacking Countries:**
- China: 3,899
- Mexico: 1,245
- United States: 782
- Canada: 151
- Romania: 74

**Notable IP Reputations:**
- known attacker: 1,191
- mass scanner: 148
- bot, crawler: 2

**Common Alert Categories:**
- Generic Protocol Command Decode: 1,036
- Misc activity: 383
- Misc Attack: 379
- Attempted Information Leak: 74
- Potentially Bad Traffic: 19

**Alert Signatures:**
- 2200003, SURICATA IPv4 truncated packet: 309
- 2200122, SURICATA AF-PACKET truncated packet: 309
- 2100560, GPL INFO VNC server response: 226
- 2228000, SURICATA SSH invalid banner: 201
- 2210061, SURICATA STREAM spurious retransmission: 123

**ASN Information:**
- 4134, Chinanet: 3,886
- 22884, TOTAL PLAY TELECOMUNICACIONES SA DE CV: 1,243
- 47890, Unmanaged Ltd: 214
- 396982, Google LLC: 199
- 209334, Modat B.V.: 139

**Source IP Addresses:**
- 218.21.0.230: 3,886
- 187.251.232.240: 1,240
- 185.242.226.45: 78
- 130.12.180.95: 74
- 85.217.149.24: 47

**Country to Port Mapping:**
- **Canada:**
  - 8728: 7
  - 30701: 3
  - 1553: 2
  - 16060: 2
  - 48005: 2
- **China:**
  - 22: 777
  - 2222: 3
  - 6379: 3
  - 27017: 3
  - 7777: 2
- **Mexico:**
  - 445: 1,240
  - 23: 1
  - 5555: 1
  - 6007: 1
- **Romania:**
  - 22: 8
  - 2692: 2
  - 12380: 2
  - 16639: 2
  - 21238: 2
- **United States:**
  - 1080: 53
  - 1962: 41
  - 5984: 37
  - 445: 16
  - 8728: 12

**CVEs Exploited:**
- CVE-2025-55182 CVE-2025-55182: 2
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 1
- CVE-2024-14007 CVE-2024-14007: 1
- CVE-2025-34036 CVE-2025-34036: 1

**Usernames:**
- root: 803
- user: 13
- admin: 8
- sol: 6
- postgres: 2
- ubuntu: 2
- 1: 1
- 123: 1
- 12345: 1
- 123456: 1

**Passwords:**
- (empty): 5
- 123456: 5
- admin: 4
- 123: 3
- paradis: 2

**OS Distribution:**
- Linux 2.2.x-3.x: 13,529
- Windows NT kernel: 12,576
- Linux 2.2.x-3.x (barebone): 330
- Windows NT kernel 5.x: 205
- Linux 2.2.x-3.x (no timestamps): 183

**Hyper-aggressive IPs:**
- 218.21.0.230: 3,886 attacks
- 187.251.232.240: 1,240 attacks
