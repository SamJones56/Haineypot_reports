# Honeypot Attack Report - 2026-02-23T15:00:24Z

## Executive Summary:
- **High Attack Volume:** A total of 8,211 attacks were observed in the past hour, with a significant concentration from the United States.
- **Dominant Attacker:** The IP address 165.245.134.97, associated with DigitalOcean, was responsible for a substantial portion of the attacks (2,412).
- **Common Tactics:** The most frequent attack signature was "GPL INFO SOCKS Proxy attempt" (938 occurrences), indicating attempts to use the server as a proxy.
- **Credential Brute-Forcing:** Brute-force attempts were prevalent, with "root" being the most targeted username (358 attempts) and "123456" the most common password (192 attempts).
- **Targeted Ports:** Port 1080 (SOCKS proxy) was the most targeted port, primarily from US-based IPs. Port 22 (SSH) was also heavily targeted from multiple countries.
- **OS Distribution:** The attacking systems were predominantly identified as Windows NT kernel and Linux-based systems.

## Detailed Analysis:

**Total Attacks:**
- 8,211

**Top Attacking Countries:**
- United States: 5,012
- Australia: 683
- Singapore: 664
- Netherlands: 582
- United Kingdom: 258

**Notable IP Reputations:**
- known attacker: 3,671
- mass scanner: 154

**Common Alert Categories:**
- Attempted Information Leak: 1,008
- Misc activity: 522
- Generic Protocol Command Decode: 349
- Misc Attack: 326
- Potentially Bad Traffic: 20

**Alert Signatures:**
- 2100615 - GPL INFO SOCKS Proxy attempt: 938
- 2100560 - GPL INFO VNC server response: 220
- 2228000 - SURICATA SSH invalid banner: 167
- 2001978 - ET INFO SSH session in progress on Expected Port: 137
- 2402000 - ET DROP Dshield Block Listed Source group 1: 111

**ASN Information:**
- 14061 (DigitalOcean, LLC): 5,578
- 46844 (Sharktech): 1,196
- 47890 (Unmanaged Ltd): 319
- 51852 (Private Layer INC): 187
- 131427 (AOHOAVIET): 175

**Source IP Addresses:**
- 165.245.134.97: 2,412
- 64.32.31.2: 1,196
- 134.199.164.233: 253
- 170.64.235.148: 250
- 129.212.228.104: 235

**Country to Port Mapping:**
- **Australia:**
  - 22: 117
  - 2222: 1
- **Netherlands:**
  - 22: 85
  - 6036: 8
  - 6037: 8
  - 8728: 7
  - 17000: 4
- **Singapore:**
  - 22: 117
  - 9714: 3
  - 5006: 2
  - 23: 1
  - 2222: 1
- **United Kingdom:**
  - 22: 30
  - 5432: 6
  - 4444: 4
  - 80: 3
  - 443: 2
- **United States:**
  - 1080: 1,196
  - 22: 583
  - 5902: 112
  - 5903: 58
  - 5901: 53

**CVEs Exploited:**
- CVE-2025-55182: 8
- CVE-2024-14007: 6
- CVE-2021-3449: 2
- CVE-2019-11500: 1
- CVE-2023-26801: 1

**Usernames:**
- root: 358
- admin: 63
- user: 28
- test: 17
- ubuntu: 17
- git: 16
- oracle: 16
- postgres: 15
- 12345: 12
- 123: 10

**Passwords:**
- 123456: 192
- 123: 52
- 1234: 39
- password: 28
- 12345678: 27

**OS Distribution:**
- Windows NT kernel: 18,476
- Linux 2.2.x-3.x: 16,316
- Linux 2.2.x-3.x (barebone): 213
- Windows NT kernel 5.x: 188
- Linux 2.2.x-3.x (no timestamps): 126

**Hyper-aggressive IPs:**
- 165.245.134.97: 2,412 attacks
- 64.32.31.2: 1,196 attacks
