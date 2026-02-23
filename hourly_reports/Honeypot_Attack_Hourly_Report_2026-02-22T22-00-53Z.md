# Honeypot Attack Report - 2026-02-22T22:00:17Z

Executive Summary:
- Total attacks in the last hour reached 7,206.
- The United States was the top attacking country with 2,036 attacks, followed by Tunisia and the United Kingdom.
- The most prominent attacker IP was 197.14.55.168 with 1,176 attacks, originating from Tunisia and associated with the ASN TUNISIANA.
- "Generic Protocol Command Decode" was the most frequent alert category.
- The most observed alert signatures were "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet".
- Common credentials remain weak, with "root", "admin", and "test" for usernames, and "123456" and "password" for passwords.

Detailed Analysis:

Total Attacks:
- 7206

Top Attacking Countries:
- United States: 2036
- Tunisia: 1176
- United Kingdom: 1175
- Germany: 639
- Canada: 445

Notable IP Reputations:
- known attacker: 2026
- mass scanner: 111
- bot, crawler: 4

Common Alert Categories:
- Generic Protocol Command Decode: 7954
- Misc activity: 508
- Misc Attack: 255
- Attempted Information Leak: 156
- Attempted Administrator Privilege Gain: 57

Alert Signatures:
- 2200003 - SURICATA IPv4 truncated packet: 3789
- 2200122 - SURICATA AF-PACKET truncated packet: 3789
- 2100560 - GPL INFO VNC server response: 228
- 2228000 - SURICATA SSH invalid banner: 181
- 2001978 - ET INFO SSH session in progress on Expected Port: 140

ASN Information:
- 14061 - DigitalOcean, LLC: 3645
- 37693 - TUNISIANA: 1176
- 210006 - Shereverov Marat Ahmedovich: 355
- 47890 - Unmanaged Ltd: 289
- 202425 - IP Volume inc: 255

Source IP Addresses:
- 197.14.55.168: 1176
- 167.172.56.108: 515
- 146.190.246.58: 439
- 178.20.210.32: 355
- 107.170.92.75: 295

Country to Port Mapping:
- Tunisia
  - 445: 1176
- United Kingdom
  - 22: 229
  - 80: 3
  - 3629: 3
- United States
  - 1025: 354
  - 22: 140
  - 5902: 115

CVEs Exploited:
- CVE-2024-14007 CVE-2024-14007
- CVE-2021-3449 CVE-2021-3449
- CVE-2024-4577 CVE-2002-0953
- CVE-2024-4577 CVE-2024-4577
- CVE-2025-55182 CVE-2025-55182

Usernames:
- root: 166
- admin: 67
- test: 63
- user: 48
- git: 41
- ftp: 28
- guest: 21
- ubuntu: 16
- deploy: 15
- developer: 15

Passwords:
- 123456: 41
- password: 36
- 123: 28
- 1234: 27
- 12345678: 26

OS Distribution:
- Linux 2.2.x-3.x: 13520
- Windows NT kernel: 2338
- Linux 2.2.x-3.x (barebone): 299
- Windows NT kernel 5.x: 72
- Linux 3.11 and newer: 47

Hyper-aggressive IPs:
- 197.14.55.168: 1176
