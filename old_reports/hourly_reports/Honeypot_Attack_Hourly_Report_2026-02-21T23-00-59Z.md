
# Honeypot Attack Report - 2026-02-21T23:00:21Z

**Executive Summary:**
- The honeypot network observed 4362 attacks in the past hour.
- India and the United States were the most active attacking countries, with 1243 and 1131 attacks respectively.
- The most prominent attacker IP was 125.20.197.82 with 873 attacks, associated with AS9498 (BHARTI Airtel Ltd.).
- "Generic Protocol Command Decode" was the most common alert category.
- The most frequent alert signature was "GPL INFO VNC server response" (2100560).
- The most targeted port was 445, primarily from India and Indonesia.

**Detailed Analysis:**

**Total Attacks:**
- 4362

**Top Attacking Countries:**
- India: 1243
- United States: 1131
- Germany: 391
- Canada: 389
- Indonesia: 309

**Notable IP Reputations:**
- known attacker: 2020
- mass scanner: 88

**Common Alert Categories:**
- Generic Protocol Command Decode: 512
- Misc activity: 489
- Misc Attack: 313
- Attempted Information Leak: 67
- Attempted Administrator Privilege Gain: 25
- Potentially Bad Traffic: 19
- Detection of a Network Scan: 5
- Detection of a Denial of Service Attack: 3
- Not Suspicious Traffic: 2
- Web Application Attack: 2

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 264
- 2228000 - SURICATA SSH invalid banner: 212
- 2001984 - ET INFO SSH session in progress on Unusual Port: 96
- 2200003 - SURICATA IPv4 truncated packet: 91
- 2200122 - SURICATA AF-PACKET truncated packet: 91
- 2402000 - ET DROP Dshield Block Listed Source group 1: 67
- 2001978 - ET INFO SSH session in progress on Expected Port: 62
- 2009582 - ET SCAN NMAP -sS window 1024: 44
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 35
- 2210051 - SURICATA STREAM Packet with broken ack: 31

**ASN Information:**
- 9498 - BHARTI Airtel Ltd.: 1243
- 47890 - Unmanaged Ltd: 440
- 209334 - Modat B.V.: 382
- 210006 - Shereverov Marat Ahmedovich: 355
- 38511 - PT Remala Abadi: 309
- 202425 - IP Volume inc: 263
- 131427 - AOHOAVIET: 250
- 14061 - DigitalOcean, LLC: 216
- 396982 - Google LLC: 188
- 4837 - CHINA UNICOM China169 Backbone: 64

**Source IP Addresses:**
- 125.20.197.82: 873
- 59.145.41.149: 370
- 178.20.210.32: 355
- 115.124.85.161: 309
- 103.53.231.159: 250
- 185.242.226.45: 123
- 129.212.184.194: 114
- 92.118.39.95: 95
- 193.32.162.145: 88
- 80.94.92.182: 80

**Country to Port Mapping:**
- Canada:
  - 1025: 6
  - 2966: 4
  - 5001: 4
  - 5415: 4
  - 7708: 4
  - 8728: 4
  - 49152: 4
  - 6379: 3
  - 16022: 3
  - 1068: 2
- China:
  - 23: 24
  - 9000: 12
  - 1494: 6
  - 9042: 5
  - 12350: 5
  - 1433: 4
  - 6379: 3
  - 47001: 3
  - 8015: 2
  - 25: 1
- Germany:
  - 22: 71
  - 9211: 4
  - 36478: 4
  - 49152: 4
  - 13248: 2
  - 18201: 2
  - 21494: 2
  - 23441: 2
  - 23763: 2
  - 25109: 2
- India:
  - 445: 1243
- Indonesia:
  - 445: 310
- Netherlands:
  - 9100: 16
  - 17001: 8
  - 81: 4
  - 17000: 4
  - 22: 2
  - 80: 2
  - 3306: 2
  - 8545: 2
  - 443: 1
  - 5200: 1
- Romania:
  - 22: 34
  - 1975: 2
  - 3569: 2
  - 5473: 2
  - 6284: 2
  - 12205: 2
  - 14866: 2
  - 22380: 2
  - 26707: 2
  - 27094: 2
- United Kingdom:
  - 22001: 8
  - 80: 2
  - 8081: 2
  - 9000: 2
  - 9476: 2
  - 14100: 2
  - 18887: 2
  - 20443: 2
  - 22096: 2
  - 40389: 2
- United States:
  - 5902: 122
  - 5901: 54
  - 11211: 38
  - 63406: 31
  - 22: 28
  - 2323: 12
  - 34567: 10
  - 25: 9
  - 3050: 9
  - 10009: 9
- Vietnam:
  - 22: 50

**CVEs Exploited:**
- CVE-2006-2369: 19
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2023-46604 CVE-2023-46604 CVE-2023-46604: 2
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- root: 21
- ubuntu: 13
- admin: 12
- user: 8
- jessica: 7
- margaret: 7
- sol: 7
- administrator: 6
- karen: 6
- nancy: 6

**Passwords:**
- 123456: 23
- 12345678: 18
- 1234: 17
- 123: 14
- test: 6
- : 5
- solana: 5
- 111111: 3
- 1q2w3e4r: 3
- admin: 3

**OS Distribution:**
- Linux 2.2.x-3.x: 5627
- Windows NT kernel: 11879
- Linux 2.2.x-3.x (barebone): 356
- Windows NT kernel 5.x: 147
- Linux 3.11 and newer: 57
- Linux 2.2.x-3.x (no timestamps): 360
- Windows 7 or 8: 693
- Linux 2.4.x-2.6.x: 41
- FreeBSD: 1
- Linux 3.x: 1

**Hyper-aggressive IPs:**
- 125.20.197.82: 873
- 59.145.41.149: 370
- 178.20.210.32: 355
- 115.124.85.161: 309
