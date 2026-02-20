# Honeypot Attack Report - 2026-02-20T00:00:17Z

**Executive Summary:**
- A high volume of attacks (8,907) were observed in the last hour, with a significant concentration from a single IP address in Vietnam.
- The dominant attacker (103.237.145.16), associated with ASN 131414 (Long Van Soft Solution JSC), was responsible for over half of the total attacks.
- "GPL INFO VNC server response" was the most frequent alert signature, indicating widespread scanning for VNC servers.
- The majority of attacks were classified as "Misc activity," suggesting a broad range of scanning and probing activities.
- The most common username and password combination was "root" with simple numerical passwords (e.g., "12345", "123456").
- The most frequently observed operating system was Windows NT kernel 5.x, followed by Linux 2.2.x-3.x.

**Detailed Analysis:**

**Total Attacks:**
8907

**Top Attacking Countries:**
- Vietnam: 5232
- United States: 1109
- Singapore: 727
- India: 531
- Germany: 478

**Notable IP Reputations:**
- known attacker: 6793
- mass scanner: 167

**Common Alert Categories:**
- Misc activity: 2423
- Generic Protocol Command Decode: 489
- Misc Attack: 403
- Attempted Information Leak: 69
- Potentially Bad Traffic: 38

**Alert Signatures:**
- 2100560, GPL INFO VNC server response: 2294
- 2200003, SURICATA IPv4 truncated packet: 188
- 2200122, SURICATA AF-PACKET truncated packet: 188
- 2402000, ET DROP Dshield Block Listed Source group 1: 140
- 2001978, ET INFO SSH session in progress on Expected Port: 65

**ASN Information:**
- 131414, Long Van Soft Solution JSC: 5232
- 14061, DigitalOcean, LLC: 1565
- 8075, Microsoft Corporation: 419
- 202425, IP Volume inc: 255
- 396982, Google LLC: 236

**Source IP Addresses:**
- 103.237.145.16: 5232
- 139.59.82.171: 530
- 207.154.211.38: 440
- 4.145.113.4: 383
- 152.42.206.51: 343

**Country to Port Mapping:**
- Germany:
  - 22: 88
  - 445: 9
  - 5351: 7
  - 2335: 4
  - 2379: 4
- India:
  - 22: 106
  - 22122: 1
- Singapore:
  - 22: 67
  - 5902: 39
  - 5903: 39
  - 5905: 39
  - 5901: 38
- United States:
  - 8728: 15
  - 1911: 13
  - 45003: 13
  - 2108: 11
  - 10443: 11
- Vietnam:
  - 22: 1046

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2025-55182 CVE-2025-55182: 4

**Usernames:**
- root: 1053
- debian: 22
- admin: 14
- backup: 13
- daemon: 13
- dev: 13
- es: 13
- ftptest: 13
- ftpuser: 13
- git: 13

**Passwords:**
- 12345: 25
- 123456: 25
- 1234567: 24
- 12345678: 24
- 123456789: 24

**OS Distribution:**
- Linux 2.2.x-3.x: 8458
- Windows NT kernel 5.x: 10007
- Linux 2.2.x-3.x (barebone): 591
- Windows NT kernel: 443
- Linux 3.11 and newer: 48

**Hyper-aggressive IPs:**
- 103.237.145.16: 5232
- 139.59.82.171: 530
- 207.154.211.38: 440
- 4.145.113.4: 383
- 152.42.206.51: 343
