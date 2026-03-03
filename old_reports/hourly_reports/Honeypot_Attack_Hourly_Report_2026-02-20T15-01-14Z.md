# Honeypot Attack Report - 2026-02-20T15:00:22Z

Executive Summary:
- France and the United States were the top attacking countries, with a significant number of attacks originating from Bucklog SARL and CANTV Servicios in Venezuela.
- The most common alert signature was "GPL INFO VNC server response" (2100560), indicating widespread VNC service scanning.
- A large portion of attacking IPs (2080) are already flagged as "known attackers".
- Attackers primarily targeted port 445 (SMB) from Venezuela and Bangladesh, and port 80 (HTTP) from France.
- Default credentials such as "root", "sa", and "admin" with common passwords like "123456" and "password" were frequently used in brute-force attempts.
- The attacking systems are predominantly identified as Windows and Linux-based systems.

Detailed Analysis:

Total Attacks:
- 3686

Top Attacking Countries:
- France: 836
- United States: 726
- Venezuela: 428
- Bangladesh: 368
- Netherlands: 298

Notable IP Reputations:
- known attacker: 2080
- mass scanner: 218
- bot, crawler: 2

Common Alert Categories:
- Misc activity: 2431
- Attempted Information Leak: 865
- Misc Attack: 389
- Generic Protocol Command Decode: 284
- Potentially Bad Traffic: 42

Alert Signatures:
- 2100560 - GPL INFO VNC server response: 2246
- 2002824 - ET INFO CURL User Agent: 781
- 2402000 - ET DROP Dshield Block Listed Source group 1: 98
- 2200003 - SURICATA IPv4 truncated packet: 63
- 2200122 - SURICATA AF-PACKET truncated packet: 63

ASN Information:
- AS211590 - Bucklog SARL: 784
- AS8048 - CANTV Servicios, Venezuela: 428
- AS63526 - Systems Solutions & development Technologies Limited: 368
- AS396982 - Google LLC: 319
- AS16509 - Amazon.com, Inc.: 237

Source IP Addresses:
- 190.202.21.118: 428
- 185.177.72.49: 392
- 185.177.72.51: 387
- 103.231.239.109: 368
- 46.19.137.194: 224

Country to Port Mapping:
- Bangladesh
  - 445: 368
- France
  - 80: 784
  - 3128: 3
  - 2010: 2
  - 2376: 2
  - 2483: 2
- Netherlands
  - 443: 194
  - 27017: 21
  - 6037: 12
  - 6036: 8
  - 17000: 8
- United States
  - 81: 15
  - 5001: 12
  - 58000: 12
  - 445: 11
  - 22: 10
- Venezuela
  - 445: 428

CVEs Exploited:
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2002-1149: 3
- CVE-2023-46604 CVE-2023-46604 CVE-2023-46604: 2
- CVE-2024-44000 CVE-2024-44000: 2
- CVE-2002-0013 CVE-2002-0012: 1

Usernames:
- root: 24
- sa: 21
- solana: 12
- sol: 10
- solv: 8
- ubuntu: 8
- admin: 7
- sshd: 4
- osmc: 3
- anonymous: 2

Passwords:
- solana: 9
- 123456: 6
- 0l0ctyQh243O63uD: 5
- password: 5
- : 4

OS Distribution:
- Windows NT kernel: 17202
- Linux 2.2.x-3.x: 15635
- Windows NT kernel 5.x: 9873
- Linux 2.2.x-3.x (barebone): 254
- Linux 2.2.x-3.x (no timestamps): 75

Hyper-aggressive IPs:
- 190.202.21.118: 428
- 185.177.72.49: 392
- 185.177.72.51: 387
- 103.231.239.109: 368
- 46.19.137.194: 224
