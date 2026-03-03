# Honeypot Attack Report - 2026-02-23T02:00:20Z

Executive Summary:
- Over 5,000 attacks were observed in the past hour, with the majority originating from the United States, India, and Germany.
- The most prominent attacking ASN was DigitalOcean, LLC, accounting for over half of all observed attacks.
- A significant portion of attackers were identified with a "known attacker" reputation.
- The most common attack vectors involved VNC and SSH protocols, with "GPL INFO VNC server response" being the top alert signature.
- Brute-force attempts were common, with "root" and "admin" as the most frequently used usernames.
- The majority of attacking systems appear to be running Linux-based operating systems.

Detailed Analysis:

Total Attacks:
- 5024

Top Attacking Countries:
- United States: 1428
- India: 1147
- Germany: 716
- Australia: 661
- Netherlands: 271

Notable IP Reputations:
- known attacker: 1481
- mass scanner: 164

Common Alert Categories:
- Misc activity: 528
- Misc Attack: 418
- Generic Protocol Command Decode: 374
- Attempted Information Leak: 62
- Potentially Bad Traffic: 11

Alert Signatures:
- 2100560 - GPL INFO VNC server response: 226
- 2228000 - SURICATA SSH invalid banner: 200
- 2402000 - ET DROP Dshield Block Listed Source group 1: 182
- 2001978 - ET INFO SSH session in progress on Expected Port: 109
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 99

ASN Information:
- 14061 - DigitalOcean, LLC: 2820
- 9498 - BHARTI Airtel Ltd.: 592
- 47890 - Unmanaged Ltd: 274
- 131427 - AOHOAVIET: 200
- 396982 - Google LLC: 146

Source IP Addresses:
- 59.145.41.149: 592
- 139.59.157.178: 497
- 64.227.169.177: 496
- 209.38.29.7: 363
- 170.64.234.58: 296

Country to Port Mapping:
- Australia
  - 22: 126
- Germany
  - 22: 128
  - 6443: 14
  - 8169: 3
  - 16403: 3
  - 9000: 2
- India
  - 445: 592
  - 22: 103
  - 443: 2
  - 1177: 2
- Netherlands
  - 22: 39
  - 17001: 16
  - 6036: 8
  - 6037: 8
  - 9100: 8
- United States
  - 5902: 115
  - 22: 89
  - 1050: 78
  - 5903: 58
  - 5901: 54

CVEs Exploited:
- CVE-2024-14007: 5
- CVE-2025-55182: 1

Usernames:
- root: 181
- admin: 125
- oracle: 41
- postgres: 38
- ubuntu: 29
- user: 21
- guest: 10
- test: 10
- vpn: 10
- gnats: 8

Passwords:
- 1234: 33
- 123: 32
- 123456: 28
- 12345678: 24
- 12345: 16

OS Distribution:
- Linux 2.2.x-3.x: 10039
- Windows NT kernel: 2652
- Linux 2.2.x-3.x (barebone): 292
- Windows NT kernel 5.x: 160
- Linux 2.2.x-3.x (no timestamps): 171

Hyper-aggressive IPs:
- 59.145.41.149: 592 attacks
- 139.59.157.178: 497 attacks
- 64.227.169.177: 496 attacks
- 209.38.29.7: 363 attacks
- 170.64.234.58: 296 attacks
