# Honeypot Attack Report - 2026-02-21T18:00:17Z

## Executive Summary:
- Total attacks in the last hour reached 3,767.
- The United States was the top attacking country with 922 attacks, followed by Qatar with 595.
- The most prominent attacker IP was 178.153.127.226 with 595 attacks, associated with ASN 8781 (Ooredoo Q.S.C.).
- "Generic Protocol Command Decode" was the most frequent alert category, with "GPL INFO VNC server response" being a leading signature.
- Common credential stuffing attempts involved usernames like 'root' and 'admin' with simple passwords such as '123456'.
- The dominant attacking OS identified was Linux 2.2.x-3.x.

## Detailed Analysis:

**Total Attacks:**
- 3767

**Top Attacking Countries:**
- United States: 922
- Qatar: 595
- Germany: 417
- United Kingdom: 377
- Australia: 355

**Notable IP Reputations:**
- known attacker: 1781
- mass scanner: 98
- bot, crawler: 1

**Common Alert Categories:**
- Generic Protocol Command Decode: 777
- Misc activity: 460
- Misc Attack: 296
- Attempted Information Leak: 62
- Potentially Bad Traffic: 15

**Alert Signatures:**
- 2100560, GPL INFO VNC server response: 228
- 2228000, SURICATA SSH invalid banner: 224
- 2200003, SURICATA IPv4 truncated packet: 223
- 2200122, SURICATA AF-PACKET truncated packet: 223
- 2001984, ET INFO SSH session in progress on Unusual Port: 106

**ASN Information:**
- 14061, DigitalOcean, LLC: 901
- 8781, Ooredoo Q.S.C.: 595
- 47890, Unmanaged Ltd: 397
- 210006, Shereverov Marat Ahmedovich: 365
- 131427, AOHOAVIET: 280

**Source IP Addresses:**
- 178.153.127.226: 595
- 178.20.210.32: 365
- 170.64.225.183: 355
- 159.65.24.56: 326
- 103.53.231.159: 280

**Country to Port Mapping:**
- Australia:
  - 22: 71
- Germany:
  - 22: 73
  - 8086: 8
  - 8007: 4
  - 8728: 4
  - 17690: 4
- Qatar:
  - 445: 596
- United Kingdom:
  - 22: 61
  - 50050: 9
  - 80: 3
  - 443: 2
  - 9036: 2
- United States:
  - 5902: 114
  - 5901: 54
  - 1434: 37
  - 23389: 31
  - 8728: 25

**CVEs Exploited:**
- CVE-2025-55182 CVE-2025-55182: 3
- CVE-2024-14007 CVE-2024-14007: 2

**Usernames:**
- root: 37
- admin: 31
- ubuntu: 22
- sol: 11
- andrew: 8
- matthew: 8
- steven: 8
- user: 8
- anthony: 7
- kenneth: 7

**Passwords:**
- 123456: 47
- 12345678: 28
- 123: 24
- 1234: 19
- password: 7

**OS Distribution:**
- Linux 2.2.x-3.x: 14656
- Windows NT kernel: 10570
- Linux 2.2.x-3.x (barebone): 327
- Windows NT kernel 5.x: 120
- Linux 2.2.x-3.x (no timestamps): 303

**Hyper-aggressive IPs:**
- 178.153.127.226: 595
- 178.20.210.32: 365
- 170.64.225.183: 355
- 159.65.24.56: 326
