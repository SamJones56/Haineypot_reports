# Honeypot Attack Report - 2026-02-22T01:00:21Z

## Executive Summary:
- A total of 4,631 attacks were observed in the past hour.
- The United States was the most active attacking country, responsible for 2,172 attacks.
- The most prolific attacker IP was 144.202.31.88 with 831 attacks, associated with ASN 20473 (The Constant Company, LLC).
- A significant portion of attacks (1,861) were from IPs with a "known attacker" reputation.
- "Generic Protocol Command Decode" was the most common alert category, with 733 instances.
- The most frequent alert signature was "SURICATA SSH invalid banner" (262 occurrences).

## Detailed Analysis:

**Total Attacks:**
- 4631

**Top Attacking Countries:**
- United States: 2172
- Germany: 482
- Australia: 357
- Romania: 264
- Vietnam: 257

**Notable IP Reputations:**
- known attacker: 1861
- mass scanner: 104
- bot, crawler: 1

**Common Alert Categories:**
- Generic Protocol Command Decode: 733
- Misc activity: 535
- Misc Attack: 324
- Attempted Information Leak: 67
- Web Application Attack: 52

**Alert Signatures:**
- 2228000, SURICATA SSH invalid banner: 262
- 2100560, GPL INFO VNC server response: 222
- 2200003, SURICATA IPv4 truncated packet: 160
- 2200122, SURICATA AF-PACKET truncated packet: 160
- 2001984, ET INFO SSH session in progress on Unusual Port: 129

**ASN Information:**
- 14061, DigitalOcean, LLC: 1206
- 20473, The Constant Company, LLC: 831
- 47890, Unmanaged Ltd: 414
- 210006, Shereverov Marat Ahmedovich: 360
- 131427, AOHOAVIET: 255

**Source IP Addresses:**
- 144.202.31.88: 831
- 178.20.210.32: 360
- 209.38.19.117: 355
- 103.53.231.159: 255
- 46.101.90.115: 176

**Country to Port Mapping:**
- Australia
  - 22: 71
- Germany
  - 22: 84
  - 443: 11
  - 8008: 4
  - 22484: 4
  - 28796: 4
- Romania
  - 22: 44
  - 3788: 2
  - 4288: 2
  - 6128: 2
  - 18445: 2
- United States
  - 2323: 375
  - 23: 228
  - 5902: 115
  - 5903: 57
  - 5901: 55
- Vietnam
  - 22: 51
  - 23: 1

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2025-55182 CVE-2025-55182: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1

**Usernames:**
- root: 87
- postgres: 38
- admin: 31
- user: 14
- ubuntu: 12
- test: 10
- sol: 9
- deborah: 8
- ftpuser: 7
- oracle: 7

**Passwords:**
- 1234: 25
- 123456: 24
- 123: 23
- 12345678: 18
- admin: 10

**OS Distribution:**
- Windows NT kernel: 11462
- Linux 2.2.x-3.x: 5031
- Linux 2.2.x-3.x (barebone): 373
- Linux 2.2.x-3.x (no timestamps): 294
- Windows NT kernel 5.x: 126

**Hyper-aggressive IPs:**
- 144.202.31.88: 831
- 178.20.210.32: 360
- 209.38.19.117: 355
- 103.53.231.159: 255
- 46.101.90.115: 176
