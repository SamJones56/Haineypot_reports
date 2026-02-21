# Honeypot Attack Report - 2026-02-21T20:00:22Z

Executive Summary:
- Over 3,300 attacks were recorded in the past hour, with the United States being the primary source of attacks.
- DigitalOcean, LLC was the dominant ASN, accounting for a significant portion of the observed attacks.
- A large number of attackers are already known to the security community, with "known attacker" being the most common reputation tag.
- The most common attack vectors were miscellaneous activities and generic protocol command decodes, with VNC and SSH being the most targeted services.
- Attackers attempted to exploit several vulnerabilities, including CVE-2024-14007 and CVE-2025-55182.
- Brute-force attempts were common, with "root" and "admin" being the most frequently used usernames.

Detailed Analysis:

Total Attacks:
- 3311

Top Attacking Countries:
- United States: 1049
- Germany: 781
- United Kingdom: 446
- Vietnam: 261
- Canada: 232

Notable IP Reputations:
- known attacker: 1728
- mass scanner: 84
- bot, crawler: 1

Common Alert Categories:
- Misc activity: 481
- Generic Protocol Command Decode: 452
- Misc Attack: 318
- Attempted Information Leak: 59
- Web Application Attack: 16

Alert Signatures:
- 2100560, GPL INFO VNC server response: 228
- 2228000, SURICATA SSH invalid banner: 201
- 2001984, ET INFO SSH session in progress on Unusual Port: 90
- 2001978, ET INFO SSH session in progress on Expected Port: 75
- 2038967, ET INFO SSH-2.0-Go version string Observed in Network Traffic: 72

ASN Information:
- 14061, DigitalOcean, LLC: 1071
- 47890, Unmanaged Ltd: 350
- 210006, Shereverov Marat Ahmedovich: 350
- 131427, AOHOAVIET: 261
- 202425, IP Volume inc: 239

Source IP Addresses:
- 143.110.164.137: 393
- 178.20.210.32: 350
- 209.38.212.28: 330
- 103.53.231.159: 261
- 129.212.184.194: 115

Country to Port Mapping:
- Canada
  - 9943: 5
  - 6379: 4
  - 8728: 4
  - 50100: 4
  - 3099: 3
- Germany
  - 22: 136
  - 18789: 51
  - 5005: 12
  - 8815: 4
  - 9211: 4
- United Kingdom
  - 22: 76
  - 10443: 4
  - 80: 2
  - 1114: 2
  - 7860: 2
- United States
  - 5902: 115
  - 5901: 54
  - 15671: 34
  - 27017: 32
  - 80: 23
- Vietnam
  - 22: 52

CVEs Exploited:
- CVE-2024-14007 CVE-2024-14007: 2
- CVE-2025-55182 CVE-2025-55182: 2
- CVE-2019-11500 CVE-2019-11500: 1

Usernames:
- root: 68
- admin: 40
- ubuntu: 18
- test: 15
- postgres: 14
- oracle: 13
- user: 13
- sa: 10
- gary: 8
- stephen: 7

Passwords:
- 123456: 40
- 123: 26
- 1234: 24
- 12345678: 20
- password: 13

OS Distribution:
- Linux 2.2.x-3.x: 13575
- Windows NT kernel: 11125
- Linux 2.2.x-3.x (barebone): 521
- Windows NT kernel 5.x: 132
- Linux 2.2.x-3.x (no timestamps): 377

Hyper-aggressive IPs:
- 143.110.164.137: 393
- 178.20.210.32: 350
- 209.38.212.28: 330
- 103.53.231.159: 261
- 129.212.184.194: 115
