# Honeypot Attack Report - 2026-02-24T05:00:15Z

## Executive Summary:
- **High Attack Volume:** The network observed a total of 4,917 attacks in the past hour.
- **Geographic Concentration:** Attacks are predominantly originating from the United States, India, and China, which collectively account for over 69% of the total attack volume.
- **Dominant Attacker:** A single IP address, 203.194.103.78, associated with ONEOTT INTERTAINMENT LIMITED in India, was responsible for 1,191 attacks, representing over 24% of the total volume. This IP is considered a hyper-aggressive actor.
- **Known Attacker Activity:** A significant portion of the attacks (1,412) were initiated by IPs with a reputation as "known attackers".
- **Common Exploit Attempts:** The most frequent alert signature was "SURICATA SSH invalid banner", indicating a high volume of SSH scanning and brute-force attempts. The most targeted port was 445 (SMB) in India.
- **Credential Stuffing:** The most common username and password combinations were "daemon" and "password" respectively, indicating continued reliance on default and weak credentials.

## Detailed Analysis:

**Total Attacks:**
- 4,917

**Top Attacking Countries:**
- United States: 1,323
- India: 1,206
- China: 909
- United Kingdom: 446
- Romania: 254

**Notable IP Reputations:**
- known attacker: 1,412
- mass scanner: 126
- bot, crawler: 1

**Common Alert Categories:**
- Generic Protocol Command Decode: 797
- Misc activity: 451
- Misc Attack: 317
- Attempted Information Leak: 53
- Potentially Bad Traffic: 6
- Attempted Administrator Privilege Gain: 4
- Detection of a Network Scan: 4
- Not Suspicious Traffic: 1
- Web Application Attack: 1
- access to a potentially vulnerable web application: 1

**Alert Signatures:**
- 2228000 - SURICATA SSH invalid banner: 213
- 2100560 - GPL INFO VNC server response: 196
- 2200003 - SURICATA IPv4 truncated packet: 178
- 2200122 - SURICATA AF-PACKET truncated packet: 178
- 2001984 - ET INFO SSH session in progress on Unusual Port: 98
- 2210061 - SURICATA STREAM spurious retransmission: 90
- 2402000 - ET DROP Dshield Block Listed Source group 1: 84
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 74
- 2001978 - ET INFO SSH session in progress on Expected Port: 69
- 2009582 - ET SCAN NMAP -sS window 1024: 41

**ASN Information:**
- 17665 - ONEOTT INTERTAINMENT LIMITED: 1,194
- 14061 - DigitalOcean, LLC: 984
- 37963 - Hangzhou Alibaba Advertising Co.,Ltd.: 845
- 47890 - Unmanaged Ltd: 359
- 396982 - Google LLC: 223
- 131427 - AOHOAVIET: 221
- 16509 - Amazon.com, Inc.: 122
- 51852 - Private Layer INC: 78
- 202425 - IP Volume inc: 77
- 48090 - Techoff Srv Limited: 74

**Source IP Addresses:**
- 203.194.103.78: 1,191
- 121.41.166.159: 843
- 157.245.36.181: 418
- 162.243.37.252: 305
- 103.53.231.159: 221
- 2.57.122.96: 156
- 129.212.184.194: 101
- 34.158.168.101: 99
- 46.19.137.194: 78
- 43.254.164.235: 57

**Country to Port Mapping:**
- **China:**
  - 20002: 33
  - 30005: 33
  - 33890: 33
  - 36379: 33
  - 37777: 33
  - 42080: 33
  - 46379: 33
  - 50022: 33
  - 50030: 33
  - 50070: 33
- **Hong Kong:**
  - 30005: 7
  - 2095: 5
  - 3128: 5
  - 4550: 1
  - 5904: 1
  - 5905: 1
  - 5909: 1
  - 5910: 1
  - 5912: 1
  - 5913: 1
- **India:**
  - 445: 1,194
  - 2375: 2
  - 2376: 2
  - 2377: 2
  - 4243: 2
  - 4244: 2
  - 8265: 2
  - 22: 1
- **Netherlands:**
  - 443: 97
  - 9100: 32
  - 3478: 8
  - 17000: 8
  - 17001: 8
  - 22: 6
  - 9398: 5
  - 3000: 2
  - 4096: 2
  - 14000: 2
- **Romania:**
  - 22: 41
  - 5799: 2
  - 6216: 2
  - 7004: 2
  - 8167: 2
  - 19327: 2
  - 26881: 2
  - 30355: 2
  - 50401: 2
  - 53458: 2
- **Switzerland:**
  - 15433: 77
  - 5432: 1
- **Ukraine:**
  - 443: 11
  - 22: 4
  - 3398: 4
- **United Kingdom:**
  - 22: 83
  - 80: 2
  - 2542: 1
  - 2744: 1
  - 5136: 1
  - 6228: 1
  - 8000: 1
  - 24324: 1
  - 24948: 1
  - 26144: 1
- **United States:**
  - 5902: 101
  - 22: 76
  - 6379: 64
  - 5903: 51
  - 5901: 48
  - 1512: 39
  - 29092: 34
  - 5500: 32
  - 8728: 24
  - 13390: 23
- **Vietnam:**
  - 22: 44

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- daemon: 43
- ubuntu: 28
- mysql: 26
- test: 25
- oracle: 24
- root: 18
- admin: 13
- deploy: 13
- developer: 13
- search: 13

**Passwords:**
- password: 13
- 12345678: 10
- 123456: 8
- 123456789: 8
- passw0rd: 8
- 123: 6
- 12345: 6
- 1: 5
- 1234: 5
- 1234567: 5

**OS Distribution:**
- Windows NT kernel: 11,588
- Linux 2.2.x-3.x: 10,636
- Linux 3.11 and newer: 865
- Linux 2.2.x-3.x (barebone): 363
- Windows NT kernel 5.x: 165
- Linux 2.2.x-3.x (no timestamps): 144
- Windows 7 or 8: 1,205
- Mac OS X: 9
- Linux 3.1-3.10: 6
- Linux 2.4.x-2.6.x: 5

**Hyper-aggressive IPs:**
- 203.194.103.78: 1,191
- 121.41.166.159: 843
- 157.245.36.181: 418
- 162.243.37.252: 305
- 103.53.231.159: 221
- 2.57.122.96: 156
- 129.212.184.194: 101
