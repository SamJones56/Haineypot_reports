# Honeypot Attack Report - 2026-02-20T14:00:20Z

## Executive Summary:
- The honeypot network observed 10,781 attacks in the past hour.
- A significant portion of attacks originated from Czechia, with a single IP address (88.86.119.38) responsible for 4,995 attacks.
- The most common alert signature was "GPL INFO VNC server response," indicating widespread scanning for open VNC servers.
- Attackers were observed attempting to exploit several vulnerabilities, including CVE-2021-3449 and CVE-2024-14007.
- Common usernames such as "root" and "sa" were frequently used in brute-force attempts.
- The dominant operating systems of attacking machines were identified as Linux and Windows NT.

## Detailed Analysis:

**Total Attacks:**
- 10781

**Top Attacking Countries:**
- Czechia: 4995
- Azerbaijan: 1827
- Qatar: 1146
- United States: 623
- India: 335

**Notable IP Reputations:**
- known attacker: 1485
- mass scanner: 223
- bot, crawler: 1

**Common Alert Categories:**
- Misc activity: 2383
- Generic Protocol Command Decode: 948
- Misc Attack: 463
- Potentially Bad Traffic: 76
- Attempted Information Leak: 75

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 2240
- 2200003 - SURICATA IPv4 truncated packet: 323
- 2200122 - SURICATA AF-PACKET truncated packet: 323
- 2402000 - ET DROP Dshield Block Listed Source group 1: 176
- 2001978 - ET INFO SSH session in progress on Expected Port: 72

**ASN Information:**
- 39392 - SH.cz s.r.o.: 4995
- 39232 - Uninet LLC: 1827
- 8781 - Ooredoo Q.S.C.: 1146
- 14061 - DigitalOcean, LLC: 437
- 396982 - Google LLC: 425

**Source IP Addresses:**
- 88.86.119.38: 4995
- 185.18.245.87: 1827
- 178.153.127.226: 1146
- 103.133.122.38: 314
- 83.219.7.170: 300

**Country to Port Mapping:**
- Azerbaijan
  - 445: 1827
- Czechia
  - 2323: 3471
  - 23: 762
- India
  - 445: 314
  - 22: 4
  - 22122: 1
- Qatar
  - 445: 1146
- United States
  - 8728: 28
  - 9100: 20
  - 22: 17

**CVEs Exploited:**
- CVE-2021-3449
- CVE-2024-14007
- CVE-2019-11500
- CVE-2025-55182
- CVE-2002-0013
- CVE-2002-0012

**Usernames:**
- root: 73
- sa: 58
- ubuntu: 15
- sol: 11
- solana: 11
- admin: 9
- config: 5
- user: 5
- git: 4
- guest: 4

**Passwords:**
- admin: 8
- 123: 7
- 1234: 7
- admin123: 6
- (empty): 5

**OS Distribution:**
- Linux 2.2.x-3.x: 19229
- Windows NT kernel: 17275
- Windows NT kernel 5.x: 9513
- Linux 2.2.x-3.x (barebone): 385
- Linux 2.2.x-3.x (no timestamps): 90

**Hyper-aggressive IPs:**
- 88.86.119.38: 4995 attacks
