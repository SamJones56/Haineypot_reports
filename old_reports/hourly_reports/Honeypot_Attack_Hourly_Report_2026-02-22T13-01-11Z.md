# Honeypot Attack Report - 2026-02-22T13:00:24Z

**Executive Summary:**
- **High Attack Volume:** A total of 5,291 attacks were observed in the past hour, indicating a significant level of malicious activity.
- **Dominant Attacker:** A single IP address, 200.105.151.2, originating from Bolivia, was responsible for an overwhelming majority of the attacks (1,805), demonstrating a highly targeted or automated campaign. This IP is considered hyper-aggressive.
- **Geographic Concentration:** Attacks are globally distributed, with the top five countries being Bolivia, the United States, the United Kingdom, India, and Romania.
- **Common Tactics:** The most frequent alert category was "Generic Protocol Command Decode," suggesting that attackers are attempting to exploit various network protocols.
- **Credential Stuffing:** The most commonly used username and password combinations were "root" and "123456", respectively, indicating widespread brute-force and dictionary attacks.
- **Vulnerability Exploitation:** While the volume is low, there are observed attempts to exploit several CVEs, including CVE-2025-55182.

**Detailed Analysis:**

**Total Attacks:**
- 5,291

**Top Attacking Countries:**
- Bolivia: 1,805
- United States: 910
- United Kingdom: 714
- India: 599
- Romania: 366

**Notable IP Reputations:**
- known attacker: 1,254
- mass scanner: 131

**Common Alert Categories:**
- Generic Protocol Command Decode: 612
- Misc activity: 433
- Misc Attack: 331
- Attempted Information Leak: 145
- Potentially Bad Traffic: 20

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 220
- 2228000 - SURICATA SSH invalid banner: 213
- 2200003 - SURICATA IPv4 truncated packet: 128
- 2200122 - SURICATA AF-PACKET truncated packet: 128
- 2001984 - ET INFO SSH session in progress on Unusual Port: 98

**ASN Information:**
- 26210 - AXS Bolivia S. A.: 1,805
- 14061 - DigitalOcean, LLC: 942
- 47890 - Unmanaged Ltd: 374
- 9498 - BHARTI Airtel Ltd.: 370
- 20473 - The Constant Company, LLC: 206

**Source IP Addresses:**
- 200.105.151.2: 1,805
- 159.65.92.74: 455
- 59.145.41.149: 370
- 139.59.62.156: 190
- 45.10.175.246: 128

**Country to Port Mapping:**
- **Bolivia:**
  - 445: 1805
- **India:**
  - 445: 370
  - 22: 38
  - 23: 18
- **Romania:**
  - 22: 44
  - 33333: 12
  - 33895: 10
  - 11111: 8
  - 33389: 8
- **United Kingdom:**
  - 22: 118
  - 13388: 4
  - 2012: 2
  - 3535: 2
  - 4138: 2
- **United States:**
  - 5902: 113
  - 5903: 57
  - 5901: 54
  - 4443: 47
  - 4444: 28

**CVEs Exploited:**
- CVE-2025-55182 CVE-2025-55182: 2
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2021-3449 CVE-2021-3449: 1
- CVE-2023-26801 CVE-2023-26801: 1
- CVE-2024-14007 CVE-2024-14007: 1

**Usernames:**
- root: 51
- user: 28
- oracle: 20
- test: 19
- centos: 18
- guest: 18
- ubuntu: 12
- admin: 8
- sol: 5
- user1: 5

**Passwords:**
- 123456: 28
- password: 10
- : 8
- 123: 8
- 1234: 8

**OS Distribution:**
- Windows NT kernel: 13682
- Linux 2.2.x-3.x: 11037
- Linux 2.2.x-3.x (barebone): 287
- Linux 2.2.x-3.x (no timestamps): 214
- Windows NT kernel 5.x: 169

**Hyper-aggressive IPs:**
- 200.105.151.2: 1,805 attacks