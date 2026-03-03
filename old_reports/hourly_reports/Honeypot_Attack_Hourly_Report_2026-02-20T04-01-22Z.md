# Honeypot Attack Report - 2026-02-20T04:00:20Z

## Executive Summary:
- **High Attack Volume:** The honeypot network observed a total of 3,399 attacks in the past hour.
- **Dominant Attacker Location:** The United States was the most prominent source of attacks, accounting for 1,388 incidents.
- **Top Attacker:** The IP address `64.227.172.219` was the most active, with 456 recorded attacks. DigitalOcean, LLC (ASN 14061) was the most frequent ASN, associated with 1,442 attacks.
- **Common Attack Vector:** The most common alert category was "Misc activity", with the "GPL INFO VNC server response" (ID: 2100560) being the most triggered signature.
- **Credential Stuffing:** Brute-force attempts were prevalent, with "root", "test", and "guest" being the most common usernames, and "123456" and "password" being the most common passwords.
- **Exploitation Attempts:** The most frequently observed CVE was `CVE-2024-14007`.

## Detailed Analysis:

**Total Attacks:**
- 3,399

**Top Attacking Countries:**
- United States: 1,388
- India: 466
- Singapore: 403
- United Kingdom: 343
- Netherlands: 172

**Notable IP Reputations:**
- known attacker: 1,342
- mass scanner: 203

**Common Alert Categories:**
- Misc activity: 2,449
- Generic Protocol Command Decode: 532
- Misc Attack: 430
- Attempted Information Leak: 58
- Potentially Bad Traffic: 43
- Attempted Administrator Privilege Gain: 19
- Web Application Attack: 7
- A Network Trojan was detected: 6
- Detection of a Denial of Service Attack: 3
- Detection of a Network Scan: 3

**Alert Signatures:**
- 2100560 (GPL INFO VNC server response): 2,286
- 2200003 (SURICATA IPv4 truncated packet): 196
- 2200122 (SURICATA AF-PACKET truncated packet): 196
- 2402000 (ET DROP Dshield Block Listed Source group 1): 158
- 2038967 (ET INFO SSH-2.0-Go version string Observed in Network Traffic): 73
- 2001978 (ET INFO SSH session in progress on Expected Port): 71
- 2009582 (ET SCAN NMAP -sS window 1024): 44
- 2002752 (ET INFO Reserved Internal IP Traffic): 28
- 2210051 (SURICATA STREAM Packet with broken ack): 21
- 2210048 (SURICATA STREAM reassembly sequence GAP -- missing packet(s)): 15

**ASN Information:**
- 14061 (DigitalOcean, LLC): 1,442
- 8075 (Microsoft Corporation): 412
- 396982 (Google LLC): 315
- 174 (Cogent Communications, LLC): 200
- 47890 (Unmanaged Ltd): 166
- 213412 (ONYPHE SAS): 106
- 205548 (Zouter Limited): 105
- 201002 (PebbleHost Ltd): 64
- 6939 (Hurricane Electric LLC): 57
- 138423 (CMPak Limited): 50

**Source IP Addresses:**
- 64.227.172.219: 456
- 159.203.105.250: 455
- 4.145.113.4: 387
- 167.172.50.29: 196
- 2.57.122.210: 114
- 155.117.82.87: 105
- 34.158.168.101: 99
- 223.123.43.0: 50
- 159.65.119.52: 46
- 92.118.39.72: 45

**Country to Port Mapping:**
- **India:**
  - 22: 88
  - 31999: 8
  - 23: 1
- **Netherlands:**
  - 443: 97
  - 17000: 8
  - 80: 7
  - 8728: 6
  - 22: 4
- **Singapore:**
  - 5901: 39
  - 5904: 39
  - 5906: 39
  - 5907: 39
  - 5908: 39
- **United Kingdom:**
  - 22: 37
  - 19700: 8
  - 5986: 5
  - 4848: 4
  - 5675: 4
- **United States:**
  - 22: 103
  - 8728: 14
  - 5985: 11
  - 17000: 10
  - 8081: 7

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 5
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2006-2369: 2
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- root: 55
- test: 49
- guest: 46
- admin: 25
- oracle: 17
- hadoop: 13
- master: 13
- mysql: 13
- odoo: 13
- postgres: 13

**Passwords:**
- 123456: 18
- password: 14
- 12345: 13
- 12345678: 13
- 123456789: 11
- 123: 10
- admin: 10
- welcome: 10
- 1234567: 9
- abc123: 9

**OS Distribution:**
- Windows NT kernel: 16,932
- Windows NT kernel 5.x: 9,731
- Linux 2.2.x-3.x: 7,491
- Linux 2.2.x-3.x (barebone): 526
- Linux 2.2.x-3.x (no timestamps): 37
- Linux 3.1-3.10: 26
- Mac OS X: 23
- Linux 3.11 and newer: 19
- Windows XP: 4
- Windows 7 or 8: 3

**Hyper-aggressive IPs:**
- 64.227.172.219: 456
- 159.203.105.250: 455
- 4.145.113.4: 387
- 167.172.50.29: 196
- 2.57.122.210: 114
- 155.117.82.87: 105
