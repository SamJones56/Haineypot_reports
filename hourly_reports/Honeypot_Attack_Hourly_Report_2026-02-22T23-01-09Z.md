# Honeypot Attack Report - 2026-02-22T23:00:20Z

Executive Summary:
- Over the past hour, a total of 5,778 attacks were observed.
- The majority of attacks originated from Australia (1,476) and the United States (1,360).
- DigitalOcean, LLC (AS14061) was the most prominent ASN, accounting for 3,160 of the observed attacks.
- A significant portion of attacking IPs (1,536) were identified as known attackers.
- The most frequent alert signature was "GPL INFO VNC server response" with 228 occurrences.
- Brute-force attempts were prevalent, with "root" being the most targeted username and "123456" the most common password.

Detailed Analysis:

Total Attacks:
- 5778

Top Attacking Countries:
- Australia: 1476
- United States: 1360
- India: 527
- Brazil: 512
- Singapore: 468

Notable IP Reputations:
- known attacker: 1536
- mass scanner: 91
- bot, crawler: 2

Common Alert Categories:
- Misc activity: 501
- Generic Protocol Command Decode: 399
- Misc Attack: 237
- Attempted Information Leak: 84
- Potentially Bad Traffic: 20

Alert Signatures:
- 2100560 - GPL INFO VNC server response: 228
- 2228000 - SURICATA SSH invalid banner: 165
- 2001978 - ET INFO SSH session in progress on Expected Port: 120
- 2001984 - ET INFO SSH session in progress on Unusual Port: 79
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 73

ASN Information:
- 14061, DigitalOcean, LLC: 3160
- 27699, TELEFONICA BRASIL S.A: 511
- 210006, Shereverov Marat Ahmedovich: 366
- 47890, Unmanaged Ltd: 359
- 208885, Noyobzoda Faridduni Saidilhom: 201

Source IP Addresses:
- 170.64.162.36: 1108
- 159.89.162.36: 525
- 201.1.161.225: 511
- 165.245.191.137: 452
- 170.64.188.92: 368

Country to Port Mapping:
- Australia
  - 22: 294
- Brazil
  - 445: 511
  - 80: 1
- India
  - 22: 105
  - 23: 1
- Singapore
  - 22: 92
  - 6379: 6
  - 2222: 1
  - 5901: 1
  - 5909: 1
- United States
  - 1026: 117
  - 5902: 115
  - 22: 81
  - 5903: 59
  - 5901: 54

CVEs Exploited:
- CVE-2024-14007 CVE-2024-14007
- CVE-2002-0013 CVE-2002-0012
- CVE-2006-2369
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449

Usernames:
- root: 98
- admin: 57
- user: 56
- oracle: 48
- postgres: 40
- test: 27
- acer: 20
- ubuntu: 19
- a: 13
- sol: 13

Passwords:
- 123456: 123
- 123: 28
- password: 21
- 1234: 20
- 12345678: 17

OS Distribution:
- Linux 2.2.x-3.x: 11239
- Windows NT kernel: 2367
- Linux 2.2.x-3.x (barebone): 239
- Windows NT kernel 5.x: 108
- Linux 2.2.x-3.x (no timestamps): 339

Hyper-aggressive IPs:
- 170.64.162.36: 1108 attacks
