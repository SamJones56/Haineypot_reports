# Honeypot Attack Report - 2026-02-20T16:00:24Z

Executive Summary:
- A total of 2100 attacks were observed in the past hour.
- The United States was the most active attacking country, accounting for 776 attacks.
- The most common alert signature was "GPL INFO VNC server response" with 2236 occurrences.
- The majority of attackers were identified as "known attacker" (1232) or "mass scanner" (165).
- The most active attacking IP was 174.138.95.79 with 108 attacks.
- Common usernames such as 'root', 'admin', 'user' and 'postgres' were targeted.

Detailed Analysis:

Total Attacks:
- 2100

Top Attacking Countries:
- United States: 776
- Canada: 258
- Romania: 182
- Netherlands: 126
- United Kingdom: 112

Notable IP Reputations:
- known attacker: 1232
- mass scanner: 165
- bot, crawler: 1

Common Alert Categories:
- Misc activity: 2365
- Generic Protocol Command Decode: 1159
- Misc Attack: 359
- Attempted Information Leak: 54
- Potentially Bad Traffic: 36

Alert Signatures:
- 2100560 - GPL INFO VNC server response: 2236
- 2200003 - SURICATA IPv4 truncated packet: 503
- 2200122 - SURICATA AF-PACKET truncated packet: 503
- 2402000 - ET DROP Dshield Block Listed Source group 1: 68
- 2001978 - ET INFO SSH session in progress on Expected Port: 60

ASN Information:
- 209334 - Modat B.V.: 257
- 14061 - DigitalOcean, LLC: 231
- 47890 - Unmanaged Ltd: 182
- 396982 - Google LLC: 158
- 16509 - Amazon.com, Inc.: 124

Source IP Addresses:
- 174.138.95.79: 108
- 193.32.162.145: 90
- 179.84.22.115: 79
- 173.47.59.116: 74
- 2.57.122.208: 73

Country to Port Mapping:
- Canada
  - 3387: 4
  - 6065: 4
  - 7277: 4
- Netherlands
  - 27017: 22
  - 80: 16
  - 17001: 16
- Romania
  - 22: 35
- United Kingdom
  - 22: 3
  - 5432: 3
  - 1051: 2
- United States
  - 80: 41
  - 22: 27
  - 445: 16

CVEs Exploited:
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2025-55182 CVE-2025-55182: 2
- CVE-2002-0013 CVE-2002-0012: 1

Usernames:
- postgres: 14
- root: 14
- user: 14
- ubuntu: 11
- sol: 9
- admin: 7
- solana: 7
- dbus: 4
- lighthouse: 4
- scpuser: 3

Passwords:
- Qwerty1: 9
- 1234: 6
- user: 6
- password: 5
- solana: 5

OS Distribution:
- Windows NT kernel: 17083
- Linux 2.2.x-3.x: 15484
- Windows NT kernel 5.x: 9859
- Linux 2.2.x-3.x (barebone): 278
- Linux 2.2.x-3.x (no timestamps): 198

Hyper-aggressive IPs:
- 174.138.95.79: 108
