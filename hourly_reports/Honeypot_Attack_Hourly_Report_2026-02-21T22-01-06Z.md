# Honeypot Attack Report - 2026-02-21T22:00:17Z

## Executive Summary:
- The honeypot observed 4739 attacks in the last hour.
- The majority of attacks originated from Indonesia (1381), the United States (1037), and India (847).
- The most common alert category was "Generic Protocol Command Decode" with 920 instances.
- The most frequent alert signature was "SURICATA HTTP Response excessive header repetition" (ID: 2221036) with 511 occurrences.
- The most aggressive IP address was 115.124.85.161 with 1381 attacks.
- The most common operating system observed was Windows NT kernel with 11246 instances.

## Detailed Analysis:

**Total Attacks:**
- 4739

**Top Attacking Countries:**
- Indonesia: 1381
- United States: 1037
- India: 847
- Germany: 424
- Vietnam: 257

**Notable IP Reputations:**
- known attacker: 1703
- mass scanner: 99
- tor exit node: 12

**Common Alert Categories:**
- Generic Protocol Command Decode: 920
- Misc activity: 433
- Misc Attack: 311
- Attempted Information Leak: 68
- Web Application Attack: 27
- Potentially Bad Traffic: 24
- Attempted Administrator Privilege Gain: 15
- access to a potentially vulnerable web application: 8
- A Network Trojan was detected: 6
- Detection of a Network Scan: 5

**Alert Signatures:**
- 2221036: SURICATA HTTP Response excessive header repetition: 511
- 2100560: GPL INFO VNC server response: 236
- 2228000: SURICATA SSH invalid banner: 201
- 2001984: ET INFO SSH session in progress on Unusual Port: 99
- 2402000: ET DROP Dshield Block Listed Source group 1: 62
- 2200003: SURICATA IPv4 truncated packet: 61
- 2200122: SURICATA AF-PACKET truncated packet: 61
- 2001978: ET INFO SSH session in progress on Expected Port: 53
- 2009582: ET SCAN NMAP -sS window 1024: 45
- 2038967: ET INFO SSH-2.0-Go version string Observed in Network Traffic: 18

**ASN Information:**
- 38511: PT Remala Abadi: 1381
- 14061: DigitalOcean, LLC: 770
- 9498: BHARTI Airtel Ltd.: 370
- 47890: Unmanaged Ltd: 328
- 210006: Shereverov Marat Ahmedovich: 320
- 131427: AOHOAVIET: 257
- 51852: Private Layer INC: 243
- 396982: Google LLC: 224
- 202425: IP Volume inc: 194
- 135377: UCLOUD INFORMATION TECHNOLOGY HK LIMITED: 61

**Source IP Addresses:**
- 115.124.85.161: 1381
- 143.110.180.57: 460
- 59.145.41.149: 370
- 178.20.210.32: 320
- 103.53.231.159: 257
- 46.19.137.194: 243
- 129.212.184.194: 114
- 80.94.92.182: 66
- 185.242.226.39: 60
- 165.245.138.210: 54

**Country to Port Mapping:**
- China:
  - 23: 23
  - 80: 12
  - 4840: 6
  - 10035: 3
  - 37215: 2
- France:
  - 80: 46
  - 5900: 4
  - 3128: 3
  - 443: 2
  - 4567: 2
- Germany:
  - 22: 66
  - 18789: 50
  - 5006: 16
  - 13403: 4
  - 443: 2
- India:
  - 445: 370
  - 22: 96
  - 2222: 2
  - 2082: 1
- Indonesia:
  - 445: 1382
- Netherlands:
  - 8000: 20
  - 9100: 13
  - 6036: 8
  - 6037: 8
  - 17000: 8
- Romania:
  - 22: 13
  - 3763: 2
  - 4165: 2
  - 8787: 2
  - 9145: 2
- Switzerland:
  - 54322: 241
  - 5432: 2
- United States:
  - 5902: 115
  - 5901: 57
  - 15672: 34
  - 27019: 34
  - 8728: 21
- Vietnam:
  - 22: 52

**CVEs Exploited:**
- CVE-2025-55182 CVE-2025-55182: 8
- CVE-2006-2369: 4
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-2023-26801 CVE-2023-26801: 1

**Usernames:**
- root: 21
- admin: 12
- sol: 9
- sarah: 8
- anna: 7
- jennifer: 7
- user: 7
- mary: 6
- patricia: 6
- ahmed: 5

**Passwords:**
- 12345678: 19
- 123: 17
- 1234: 16
- 123456: 15
- validator: 4
- : 3
- sol: 3
- solana: 3
- toor: 3
- 12: 2

**OS Distribution:**
- Windows NT kernel: 11246
- Linux 2.2.x-3.x: 8575
- Windows 7 or 8: 1778
- Linux 2.2.x-3.x (barebone): 443
- Linux 2.2.x-3.x (no timestamps): 441
- Windows NT kernel 5.x: 139
- Linux 3.11 and newer: 26
- Mac OS X: 10
- Linux 3.1-3.10: 4
- FreeBSD: 1

**Hyper-aggressive IPs:**
- 115.124.85.161: 1381
- 143.110.180.57: 460
- 59.145.41.149: 370
- 178.20.210.32: 320
- 103.53.231.159: 257
- 46.19.137.194: 243
