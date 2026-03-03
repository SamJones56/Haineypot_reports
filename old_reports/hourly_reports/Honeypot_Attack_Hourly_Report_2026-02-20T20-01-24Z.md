# Honeypot Attack Report - 2026-02-20T20:00:24Z

## Executive Summary:
- **High Attack Volume**: A total of 5,659 attacks were observed in the past hour, with a significant concentration from the United States and Australia.
- **Dominant Attacker**: A single IP address, 170.64.183.111, associated with DigitalOcean, was responsible for over 20% of the total attack volume, launching 1,149 attacks.
- **Geographic Concentration**: The top five attacking countries (United States, Australia, Germany, Vietnam, France) accounted for the majority of attack traffic, with Vietnam-based attacks heavily targeting port 445.
- **Common Credentials**: Brute-force attempts remain prevalent, with "root" and "admin" being the most frequently used usernames and "123456" the most common password.
- **Signature Analysis**: The most frequent alert signatures were related to truncated packets, indicating possible network evasion techniques or malformed traffic.
- **Exploitation Activity**: Low-volume probing for a variety of CVEs was observed, including CVE-2024-14007.

## Detailed Analysis:

**Total Attacks:**
- 5,659

**Top Attacking Countries:**
- United States: 1,406
- Australia: 1,148
- Germany: 802
- Vietnam: 739
- France: 427

**Notable IP Reputations:**
- known attacker: 2,469
- mass scanner: 138
- tor exit node: 6

**Common Alert Categories:**
- Generic Protocol Command Decode: 762
- Misc activity: 337
- Misc Attack: 318
- Attempted Information Leak: 76
- Potentially Bad Traffic: 17

**Alert Signatures:**
- 2200003 - SURICATA IPv4 truncated packet: 252
- 2200122 - SURICATA AF-PACKET truncated packet: 252
- 2228000 - SURICATA SSH invalid banner: 120
- 2100560 - GPL INFO VNC server response: 104
- 2001978 - ET INFO SSH session in progress on Expected Port: 103

**ASN Information:**
- 14061 - DigitalOcean, LLC: 1,975
- 7552 - Viettel Group: 724
- 47890 - Unmanaged Ltd: 480
- 210006 - Shereverov Marat Ahmedovich: 443
- 211590 - Bucklog SARL: 387

**Source IP Addresses:**
- 170.64.183.111: 1,149
- 116.96.45.105: 724
- 178.20.210.32: 443
- 107.170.39.69: 426
- 185.177.72.49: 387

**Country to Port Mapping:**
- **Australia**
  - 22: 230
- **France**
  - 80: 387
  - 3128: 3
  - 135: 2
- **Germany**
  - 22: 146
  - 80: 9
  - 6140: 4
- **United States**
  - 80: 148
  - 22: 89
  - 5672: 37
- **Vietnam**
  - 445: 724
  - 9009: 7
  - 22: 1

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2025-3248 CVE-2025-3248: 1
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- root: 164
- admin: 52
- sol: 17
- test: 16
- ubuntu: 16
- deploy: 14
- solana: 14
- user: 12
- sshd: 8
- deployer: 7

**Passwords:**
- 123456: 48
- 1234: 24
- 123: 21
- password: 20
- 12345: 16

**OS Distribution:**
- Windows NT kernel: 17,104
- Linux 2.2.x-3.x: 14,092
- Linux 2.2.x-3.x (barebone): 397
- Linux 2.2.x-3.x (no timestamps): 390
- Windows NT kernel 5.x: 94

**Hyper-aggressive IPs:**
- 170.64.183.111: 1,149
