# Honeypot Attack Report - 2026-02-21T18:15:27Z

## Executive Summary:
- **High Attack Volume:** Over 23,000 attacks were recorded in the last 6 hours, with a significant concentration from the United States, Singapore, and Australia.
- **Dominant Attacker Infrastructure:** DigitalOcean infrastructure (ASN 14061) was the source of a large portion of the attacks, indicating a potential concentration of malicious actors on this platform.
- **Common Exploit Attempts:** The most frequently observed alert category was "Generic Protocol Command Decode", suggesting a high volume of reconnaissance and protocol-level attacks. The most common alert signatures were "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet", indicating network anomalies or attempts to evade detection.
- **Hyper-Aggressive IPs:** A small number of IP addresses were responsible for a disproportionately large number of attacks. The most aggressive IP, `128.199.198.62`, launched over 4,600 attacks.
- **Credential Stuffing:** The most common username and password combinations were "root" and "123456", indicating widespread brute-force and dictionary attacks.
- **Operating System Distribution:** The vast majority of attacking systems were identified as running Linux or Windows NT kernels.

## Detailed Analysis:

**Total Attacks:**
- 23276

**Top Attacking Countries:**
- United States: 4856
- Singapore: 4643
- Australia: 3361
- Germany: 2157
- Vietnam: 1203

**Notable IP Reputations:**
- known attacker: 13570
- mass scanner: 736
- bot, crawler: 8

**Common Alert Categories:**
- Generic Protocol Command Decode: 13440
- Misc activity: 2631
- Misc Attack: 2054
- Attempted Information Leak: 713
- Attempted Administrator Privilege Gain: 119
- Potentially Bad Traffic: 95
- Web Application Attack: 36
- Detection of a Network Scan: 19
- access to a potentially vulnerable web application: 15
- Detection of a Denial of Service Attack: 9

**Alert Signatures:**
- 2200003 - SURICATA IPv4 truncated packet: 5677
- 2200122 - SURICATA AF-PACKET truncated packet: 5677
- 2100560 - GPL INFO VNC server response: 1358
- 2228000 - SURICATA SSH invalid banner: 1280
- 2001984 - ET INFO SSH session in progress on Unusual Port: 576
- 2402000 - ET DROP Dshield Block Listed Source group 1: 548
- 2001978 - ET INFO SSH session in progress on Expected Port: 327
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 327
- 2023753 - ET SCAN MS Terminal Server Traffic on Non-standard Port: 270
- 2009582 - ET SCAN NMAP -sS window 1024: 269

**ASN Information:**
- 14061 - DigitalOcean, LLC: 9212
- 210006 - Shereverov Marat Ahmedovich: 1912
- 47890 - Unmanaged Ltd: 1827
- 131427 - AOHOAVIET: 1203
- 8781 - Ooredoo Q.S.C.: 1141
- 396982 - Google LLC: 1048
- 202425 - IP Volume inc: 716
- 209334 - Modat B.V.: 536
- 51852 - Private Layer INC: 467
- 8075 - Microsoft Corporation: 367

**Source IP Addresses:**
- 128.199.198.62: 4602
- 170.64.225.183: 3361
- 178.20.210.32: 1789
- 103.53.231.159: 1203
- 178.153.127.226: 1141
- 46.19.137.194: 467
- 129.212.184.194: 456
- 159.65.24.56: 421
- 103.231.239.109: 362
- 59.145.41.149: 362

**Country to Port Mapping:**
- **Australia**
  - 22: 671
- **Germany**
  - 22: 363
  - 5580: 8
  - 5832: 8
  - 8007: 8
  - 8086: 8
- **Singapore**
  - 22: 922
  - 2082: 6
  - 80: 4
  - 8827: 3
  - 4244: 2
- **United States**
  - 5902: 457
  - 3388: 140
  - 5901: 126
  - 22: 86
  - 9093: 57
- **Vietnam**
  - 22: 241

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 15
- CVE-2025-55182 CVE-2025-55182: 14
- CVE-2021-3449 CVE-2021-3449: 9
- CVE-2019-11500 CVE-2019-11500: 6
- CVE-2002-0013 CVE-2002-0012: 4
- CVE-2023-26801 CVE-2023-26801: 2
- CVE-2023-46604 CVE-2023-46604 CVE-2023-46604: 2

**Usernames:**
- root: 1318
- admin: 98
- ubuntu: 54
- user: 43
- sol: 38
- test: 24
- centos: 20
- postgres: 20
- solana: 18
- deploy: 12

**Passwords:**
- 123456: 199
- : 88
- 123: 83
- 12345678: 74
- 1234: 67
- password: 31
- admin: 22
- 12345: 15
- P@ssw0rd: 15
- root: 15

**OS Distribution:**
- Linux 2.2.x-3.x: 82987
- Windows NT kernel: 66941
- Linux 2.2.x-3.x (barebone): 1980
- Windows NT kernel 5.x: 923
- Linux 2.2.x-3.x (no timestamps): 1359
- Linux 3.11 and newer: 213
- Mac OS X: 118
- Windows 7 or 8: 1881
- FreeBSD: 7
- Linux 2.4.x: 37

**Hyper-aggressive IPs:**
- 128.199.198.62: 4602
- 170.64.225.183: 3361
- 178.20.210.32: 1789
- 103.53.231.159: 1203
- 178.153.127.226: 1141
- 46.19.137.194: 467
- 129.212.184.194: 456
- 159.65.24.56: 421
- 103.231.239.109: 362
- 59.145.41.149: 362
