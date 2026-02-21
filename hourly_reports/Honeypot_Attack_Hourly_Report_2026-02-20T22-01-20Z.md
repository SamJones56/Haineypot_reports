# Honeypot Attack Report - 2026-02-20T22:00:20Z

**Executive Summary:**
- A high volume of attacks (12,422) were observed in the past hour.
- A single IP address, 45.175.157.3, originating from Paraguay and associated with ASN 267837 (Vicente Sosa Peralta), was responsible for the vast majority (78.6%) of the attacks.
- The most common username attempted was 'root', indicating a focus on privileged account access.
- The most frequent alert category was 'Generic Protocol Command Decode', suggesting a high level of protocol-level attacks.
- A significant number of attacks were associated with IPs flagged as 'known attacker'.
- The dominant operating systems fingerprinted were Windows NT kernel and Linux 2.2.x-3.x.

**Detailed Analysis:**

**Total Attacks:**
- 12422

**Top Attacking Countries:**
- Paraguay: 9765
- United States: 1120
- Germany: 367
- Australia: 300
- Latvia: 170

**Notable IP Reputations:**
- known attacker: 1446
- mass scanner: 142
- bot, crawler: 7

**Common Alert Categories:**
- Generic Protocol Command Decode: 855
- Misc activity: 487
- Misc Attack: 322
- Potentially Bad Traffic: 62
- Attempted Information Leak: 56

**Alert Signatures:**
- 2200003 - SURICATA IPv4 truncated packet: 263
- 2200122 - SURICATA AF-PACKET truncated packet: 263
- 2100560 - GPL INFO VNC server response: 258
- 2228000 - SURICATA SSH invalid banner: 195
- 2001984 - ET INFO SSH session in progress on Unusual Port: 104

**ASN Information:**
- 267837 (Vicente Sosa Peralta): 9765
- 14061 (DigitalOcean, LLC): 580
- 210006 (Shereverov Marat Ahmedovich): 300
- 47890 (Unmanaged Ltd): 235
- 396982 (Google LLC): 185

**Source IP Addresses:**
- 45.175.157.3: 9765
- 178.20.210.32: 300
- 134.199.171.153: 270
- 86.54.24.29: 170
- 45.79.150.125: 117

**Country to Port Mapping:**
- Australia
  - 22: 59
- Germany
  - 22: 60
  - 9100: 16
  - 9571: 7
  - 7004: 4
  - 7687: 4
- Latvia
  - 22: 35
- Paraguay
  - 22: 1953
- United States
  - 23: 112
  - 27017: 33
  - 23389: 31
  - 22: 23
  - 10021: 9

**CVEs Exploited:**
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2006-2369: 2
- CVE-2024-4577 CVE-2002-0953: 2

**Usernames:**
- root: 1995
- user: 31
- oracle: 28
- admin: 21
- sa: 17
- postgres: 14
- solana: 6
- ftp: 5
- supervisor: 5
- pi: 4

**Passwords:**
- : 20
- password: 11
- 1234: 7
- 123456: 6
- admin: 6

**OS Distribution:**
- Linux 2.2.x-3.x: 8503
- Windows NT kernel: 14411
- Linux 2.2.x-3.x (barebone): 357
- Windows NT kernel 5.x: 96
- Linux 2.2.x-3.x (no timestamps): 292

**Hyper-aggressive IPs:**
- 45.175.157.3: 9765
