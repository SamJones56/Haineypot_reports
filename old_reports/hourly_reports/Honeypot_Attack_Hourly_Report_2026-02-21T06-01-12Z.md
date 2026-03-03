# Honeypot Attack Report - 2026-02-21T06:00:13Z

## Executive Summary:
- **High Attack Volume:** A total of 2,840 attacks were observed in the past hour, with the majority originating from the United States.
- **Dominant Exploitation Technique:** The most prevalent alert signature was "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" with 1,484 occurrences, indicating a focus on exploiting a known vulnerability.
- **Top Attacker:** The IP address 134.209.180.181, associated with DigitalOcean, was the most aggressive attacker, responsible for 395 attacks.
- **Common Credentials:** Brute-force attempts commonly used standard usernames like 'admin', 'user', and 'root', with simple passwords such as 'password' and '1234'.
- **Targeted Services:** The observed port activity suggests that attackers were targeting a variety of services, with notable traffic to ports 443 (HTTPS), 15432, and 22 (SSH).
- **Attacker Infrastructure:** A significant portion of attacks originated from cloud providers, including DigitalOcean and Google.

## Detailed Analysis:

**Total Attacks:**
- 2840

**Top Attacking Countries:**
- United States: 899
- United Kingdom: 468
- Canada: 357
- Netherlands: 274
- Switzerland: 251

**Notable IP Reputations:**
- known attacker: 1887
- mass scanner: 175

**Common Alert Categories:**
- Generic Protocol Command Decode: 2187
- Attempted Administrator Privilege Gain: 1489
- Misc activity: 413
- Misc Attack: 410
- Attempted Information Leak: 70

**Alert Signatures:**
- 2024766 - ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1484
- 2200003 - SURICATA IPv4 truncated packet: 883
- 2200122 - SURICATA AF-PACKET truncated packet: 883
- 2100560 - GPL INFO VNC server response: 226
- 2228000 - SURICATA SSH invalid banner: 208

**ASN Information:**
- 14061 - DigitalOcean, LLC: 454
- 396982 - Google LLC: 448
- 209334 - Modat B.V.: 350
- 51852 - Private Layer INC: 251
- 47890 - Unmanaged Ltd: 192

**Source IP Addresses:**
- 134.209.180.181: 395
- 46.19.137.194: 251
- 34.158.168.101: 189
- 49.248.192.204: 108
- 85.217.149.18: 87

**Country to Port Mapping:**
- **Canada**
  - 2214: 4
  - 3051: 4
  - 3061: 4
  - 4445: 4
  - 8417: 4
- **Netherlands**
  - 443: 185
  - 8728: 14
  - 80: 8
  - 6037: 8
  - 22: 5
- **Switzerland**
  - 15432: 244
  - 5432: 7
- **United Kingdom**
  - 22: 79
  - 7000: 12
  - 26001: 7
  - 48501: 4
  - 80: 3
- **United States**
  - 33160: 31
  - 81: 25
  - 80: 19
  - 17000: 15
  - 8728: 14

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2010-0569: 2
- CVE-2025-55182 CVE-2025-55182: 2
- CVE-2023-26801 CVE-2023-26801: 1

**Usernames:**
- admin: 49
- user: 32
- root: 16
- postgres: 7
- Accept-Encoding: gzip: 2
- GET / HTTP/1.1: 2
- User-Agent: visionheight.com/scan Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36: 2
- payer: 2
- debian: 1
- developer: 1

**Passwords:**
- : 8
- password: 5
- 1234: 4
- 12345: 3
- 123456789: 3

**OS Distribution:**
- Linux 2.2.x-3.x: 10158
- Windows NT kernel: 9558
- Linux 2.2.x-3.x (barebone): 328
- Windows NT kernel 5.x: 173
- Linux 3.11 and newer: 44

**Hyper-aggressive IPs:**
- 134.209.180.181: 395 attacks
