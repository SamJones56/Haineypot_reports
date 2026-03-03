# Honeypot Attack Report - 2026-02-23T01:00:16Z

## Executive Summary:
- **High Volume of Attacks:** A total of 11,260 attacks were recorded in the past hour, with a significant concentration from a few key sources.
- **Dominant Attacker:** The IP address 209.38.80.88, associated with DigitalOcean, was responsible for 4,815 attacks, making it the most aggressive actor.
- **Geographic Concentration:** Australia was the top attacking country with 6,715 attacks, followed by the United States and Tunisia.
- **Common Vulnerabilities:** Attacks were observed targeting CVE-2024-14007.
- **Credential Stuffing:** The most common username and password combinations were `root` and `123456`.
- **Operating System Distribution:** The vast majority of attacking systems were identified as running Linux.

## Detailed Analysis:

**Total Attacks:**
- 11,260

**Top Attacking Countries:**
- Australia: 6,715
- United States: 1,492
- Tunisia: 1,176
- Singapore: 802
- Netherlands: 293

**Notable IP Reputations:**
- known attacker: 995
- mass scanner: 114

**Common Alert Categories:**
- Generic Protocol Command Decode: 811
- Misc activity: 485
- Misc Attack: 262
- Attempted Information Leak: 58
- Detection of a Network Scan: 8

**Alert Signatures:**
- 2200003 - SURICATA IPv4 truncated packet: 239
- 2200122 - SURICATA AF-PACKET truncated packet: 239
- 2100560 - GPL INFO VNC server response: 228
- 2228000 - SURICATA SSH invalid banner: 175
- 2001978 - ET INFO SSH session in progress on Expected Port: 107

**ASN Information:**
- 14061 - DigitalOcean, LLC: 8,510
- 37693 - TUNISIANA: 1,176
- 47890 - Unmanaged Ltd: 230
- 131427 - AOHOAVIET: 215
- 202425 - IP Volume inc: 172

**Source IP Addresses:**
- 209.38.80.88: 4,815
- 209.38.29.178: 1,539
- 197.14.55.168: 1,176
- 165.245.139.61: 513
- 165.245.190.171: 396

**Country to Port Mapping:**
- **Australia:**
  - 22: 1340
  - 8081: 10
  - 17000: 1
- **Netherlands:**
  - 22: 42
  - 9100: 16
  - 8728: 14
  - 6037: 8
  - 17000: 8
- **Singapore:**
  - 22: 155
  - 23: 2
  - 2222: 1
  - 5901: 1
  - 5909: 1
- **Tunisia:**
  - 445: 1176
- **United States:**
  - 5902: 114
  - 22: 107
  - 1029: 78
  - 5903: 56
  - 5901: 54

**CVEs Exploited:**
- CVE-2024-14007: 4
- CVE-2025-55182: 1

**Usernames:**
- root: 214
- admin: 56
- ubuntu: 46
- user: 31
- centos: 26
- test: 26
- guest: 19
- backup: 18
- es: 17
- elastic: 16

**Passwords:**
- 123456: 386
- 123: 61
- password: 47
- 12345678: 36
- 12345: 31

**OS Distribution:**
- Linux 2.2.x-3.x: 10,863
- Windows NT kernel: 2,273
- Linux 2.2.x-3.x (barebone): 236
- Windows NT kernel 5.x: 134
- Linux 2.2.x-3.x (no timestamps): 320

**Hyper-aggressive IPs:**
- 209.38.80.88: 4,815
- 209.38.29.178: 1,539
- 197.14.55.168: 1,176
