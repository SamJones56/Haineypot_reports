# Honeypot Attack Report - 2026-02-21T14:00:20Z

## Executive Summary:
- **High Attack Volume:** A total of 3,329 attacks were observed in the past hour, with a significant concentration from Singapore.
- **Dominant Attacker:** A single IP address, 128.199.198.62, originating from Singapore and associated with DigitalOcean, was responsible for a substantial portion of the attack volume (1,555 attacks).
- **Common Tactics:** The most frequent alert categories were "Generic Protocol Command Decode" and "Misc activity," suggesting a broad range of initial probing and reconnaissance activities.
- **SSH and VNC Focus:** The top alert signatures, "GPL INFO VNC server response" and "SURICATA SSH invalid banner," indicate a strong focus on compromising remote access services.
- **Credential Stuffing:** The most common username attempted was "root," a typical target for brute-force attacks.
- **Exploitation Attempts:** While not widespread, there were observed attempts to exploit several CVEs, including older vulnerabilities.

## Detailed Analysis:

**Total Attacks:**
- 3329

**Top Attacking Countries:**
- Singapore: 1559
- United States: 718
- Germany: 338
- Romania: 142
- Vietnam: 140

**Notable IP Reputations:**
- known attacker: 2804
- mass scanner: 156

**Common Alert Categories:**
- Generic Protocol Command Decode: 479
- Misc activity: 431
- Misc Attack: 398
- Attempted Information Leak: 221
- Attempted Administrator Privilege Gain: 49
- Potentially Bad Traffic: 8
- Web Application Attack: 7
- Detection of a Network Scan: 5
- Malware Command and Control Activity Detected: 5
- access to a potentially vulnerable web application: 1

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 230
- 2228000 - SURICATA SSH invalid banner: 221
- 2402000 - ET DROP Dshield Block Listed Source group 1: 147
- 2023753 - ET SCAN MS Terminal Server Traffic on Non-standard Port: 132
- 2001984 - ET INFO SSH session in progress on Unusual Port: 101
- 2210051 - SURICATA STREAM Packet with broken ack: 64
- 2200003 - SURICATA IPv4 truncated packet: 51
- 2200122 - SURICATA AF-PACKET truncated packet: 51
- 2001978 - ET INFO SSH session in progress on Expected Port: 50
- 2034857 - ET HUNTING RDP Authentication Bypass Attempt: 47

**ASN Information:**
- 14061 - DigitalOcean, LLC: 1604
- 210006 - Shereverov Marat Ahmedovich: 331
- 47890 - Unmanaged Ltd: 296
- 396982 - Google LLC: 188
- 131427 - AOHOAVIET: 140
- 6939 - Hurricane Electric LLC: 74
- 202425 - IP Volume inc: 66
- 201002 - PebbleHost Ltd: 62
- 135377 - UCLOUD INFORMATION TECHNOLOGY HK LIMITED: 49
- 63949 - Akamai Connected Cloud: 47

**Source IP Addresses:**
- 128.199.198.62: 1555
- 178.20.210.32: 264
- 103.53.231.159: 140
- 2.57.122.96: 83
- 45.87.249.145: 67
- 138.68.42.39: 39
- 50.116.2.48: 39
- 185.242.226.39: 33
- 77.90.185.18: 32
- 185.242.226.46: 31

**Country to Port Mapping:**
- **Bulgaria**
  - 22: 14
  - 80: 1
- **China**
  - 8030: 7
  - 9004: 5
  - 10092: 4
  - 12167: 4
  - 23: 3
  - 6379: 3
  - 22: 2
  - 2222: 1
- **Germany**
  - 22: 54
  - 9664: 7
  - 9667: 7
  - 5832: 4
  - 22000: 3
  - 5901: 2
  - 6366: 2
  - 6809: 2
  - 8888: 2
  - 9003: 2
- **Netherlands**
  - 80: 8
  - 8888: 4
  - 22: 2
  - 81: 2
  - 3306: 2
  - 8545: 2
  - 25565: 2
  - 1025: 1
  - 5555: 1
  - 8265: 1
- **Romania**
  - 22: 20
  - 5984: 2
  - 7615: 2
  - 11252: 2
  - 13924: 2
  - 15963: 2
  - 17255: 2
  - 18834: 2
  - 19015: 2
  - 20415: 2
- **Seychelles**
  - 6037: 8
  - 17001: 4
  - 44440: 2
  - 44444: 2
  - 44445: 2
  - 44448: 2
  - 44450: 2
  - 44456: 2
  - 44457: 2
  - 44458: 2
- **Singapore**
  - 22: 311
  - 8827: 3
  - 2222: 1
- **United Kingdom**
  - 80: 5
  - 1313: 2
  - 3111: 2
  - 3590: 2
  - 4123: 2
  - 4434: 2
  - 4516: 2
  - 4646: 2
  - 5556: 2
  - 5645: 2
- **United States**
  - 3388: 92
  - 8333: 35
  - 10000: 31
  - 9100: 20
  - 6379: 11
  - 2404: 10
  - 8001: 8
  - 11712: 8
  - 8728: 7
  - 2000: 6
- **Vietnam**
  - 22: 28

**CVEs Exploited:**
- CVE-2002-0013 CVE-2002-0012
- CVE-2023-26801 CVE-2023-26801
- CVE-2024-14007 CVE-2024-14007
- CVE-2025-55182 CVE-2025-55182

**Usernames:**
- root: 358
- admin: 8
- solana: 8
- ubuntu: 7
- sol: 3
- test: 3
- AdminGPON: 2
- Test: 2
- user: 2
- vincent: 2

**Passwords:**
- 123456: 4
- admin123: 3
- root: 3
- server: 3
- : 2
- 123: 2
- 1234567890: 2
- 1q2w3e4r: 2
- ALC#FGU: 2
- administrator: 2

**OS Distribution:**
- Linux 2.2.x-3.x: 12466
- Windows NT kernel: 11795
- Linux 2.2.x-3.x (barebone): 376
- Windows NT kernel 5.x: 153
- Linux 2.2.x-3.x (no timestamps): 215
- Linux 3.11 and newer: 37
- Mac OS X: 32
- Windows 7 or 8: 2
- FreeBSD: 1
- Linux 2.4.x: 1

**Hyper-aggressive IPs:**
- 128.199.198.62: 1555
