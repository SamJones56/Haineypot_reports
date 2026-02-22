# Honeypot Attack Report - 2026-02-22T15:00:21Z

## Executive Summary:
- **High Volume Attack Activity:** A total of 4,147 attacks were observed in the past hour, with the United States, Germany, and the United Kingdom being the top three sources of attacks.
- **Dominant Attacker:** The IP address 45.10.175.246, associated with AS55933 (Cloudie Limited), was the most active attacker, responsible for 509 attacks.
- **Exploitation of Multiple Vulnerabilities:** A variety of CVEs were targeted, with CVE-2019-11500 being the most frequently exploited.
- **Brute Force Attempts:** A significant number of login attempts used common usernames and passwords such as 'root', 'admin', '123456', and 'password'.
- **DoublePulsar Backdoor:** The most frequent alert signature was related to the DoublePulsar backdoor, indicating attempts to install this malware.
- **OS Distribution:** The majority of attacks originated from systems running Windows NT kernel and Linux 2.2.x-3.x.

## Detailed Analysis:

**Total Attacks:**
- 4147

**Top Attacking Countries:**
- United States: 1097
- Germany: 764
- United Kingdom: 618
- India: 437
- Romania: 263

**Notable IP Reputations:**
- known attacker: 1814
- mass scanner: 93
- bot, crawler: 2

**Common Alert Categories:**
- Generic Protocol Command Decode: 560
- Attempted Administrator Privilege Gain: 530
- Misc activity: 508
- Misc Attack: 277
- Attempted Information Leak: 66

**Alert Signatures:**
- 2024766 - ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 521
- 2228000 - SURICATA SSH invalid banner: 238
- 2100560 - GPL INFO VNC server response: 220
- 2001984 - ET INFO SSH session in progress on Unusual Port: 112
- 2001978 - ET INFO SSH session in progress on Expected Port: 108

**ASN Information:**
- 14061 - DigitalOcean, LLC: 1040
- 55933 - Cloudie Limited: 509
- 47890 - Unmanaged Ltd: 396
- 9498 - BHARTI Airtel Ltd.: 370
- 210006 - Shereverov Marat Ahmedovich: 355

**Source IP Addresses:**
- 45.10.175.246: 509
- 59.145.41.149: 370
- 178.20.210.32: 355
- 165.227.132.204: 153
- 103.53.231.159: 130

**Country to Port Mapping:**
- **Germany**
  - 22: 138
  - 9191: 7
  - 3601: 4
  - 8081: 4
  - 9002: 4
- **India**
  - 445: 370
  - 22: 12
  - 6379: 3
  - 25: 2
- **Romania**
  - 22: 43
  - 587: 4
  - 2237: 2
  - 2929: 2
  - 12683: 2
- **United Kingdom**
  - 22: 102
  - 5072: 4
  - 80: 3
  - 3306: 3
  - 1143: 2
- **United States**
  - 5902: 115
  - 5985: 108
  - 5903: 57
  - 5901: 54
  - 8333: 41

**CVEs Exploited:**
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2023-46604 CVE-2023-46604 CVE-2023-46604: 2
- CVE-2024-14007 CVE-2024-14007: 2
- CVE-2002-0013 CVE-2002-0012: 1
- CVE-2021-3449 CVE-2021-3449: 1

**Usernames:**
- root: 105
- admin: 57
- user: 22
- sol: 13
- backup: 8
- sync: 8
- sys: 8
- ubuntu: 8
- games: 6
- postgres: 6

**Passwords:**
- 123456: 49
- 123: 18
- 12345678: 15
- 1234: 14
- password: 11

**OS Distribution:**
- Windows NT kernel: 18481
- Linux 2.2.x-3.x: 12171
- Linux 2.2.x-3.x (no timestamps): 260
- Linux 2.2.x-3.x (barebone): 224
- Windows NT kernel 5.x: 108

**Hyper-aggressive IPs:**
- 45.10.175.246: 509
