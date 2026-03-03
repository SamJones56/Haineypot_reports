# Honeypot Attack Report - 2026-02-23T21:00:29Z

## Executive Summary:
- **High-Volume Attack Activity:** A total of 4,946 attacks were observed in the past hour, with a significant concentration from a single source IP.
- **Dominant Attacker:** The IP address `170.64.230.118`, originating from Australia and associated with DigitalOcean, was responsible for 2,563 attacks, representing over half of the total volume.
- **Geographic Concentration:** Australia was the top attacking country with 2,563 attacks, followed by the United States with 1,050.
- **Common Attack Vectors:** The most frequent alert categories were "Generic Protocol Command Decode" and "Misc activity," while credential stuffing attacks were prevalent, with "root" and "admin" as the most common usernames.
- **Exploitation Attempts:** Low numbers of exploitation attempts for CVEs were observed, including CVE-2024-14007 and CVE-2021-3449.
- **Operating System Landscape:** The majority of attacking systems were identified as Windows NT kernel and Linux 2.2.x-3.x.

## Detailed Analysis:

**Total Attacks:**
- 4,946

**Top Attacking Countries:**
- Australia: 2,563
- United States: 1,050
- Seychelles: 247
- Romania: 243
- Vietnam: 215

**Notable IP Reputations:**
- known attacker: 4,231
- mass scanner: 68

**Common Alert Categories:**
- Generic Protocol Command Decode: 937
- Misc activity: 456
- Misc Attack: 272
- Attempted Information Leak: 111
- Attempted Administrator Privilege Gain: 22

**Alert Signatures:**
- 2200003, SURICATA IPv4 truncated packet: 282
- 2200122, SURICATA AF-PACKET truncated packet: 282
- 2100560, GPL INFO VNC server response: 216
- 2228000, SURICATA SSH invalid banner: 210
- 2001984, ET INFO SSH session in progress on Unusual Port: 100

**ASN Information:**
- 14061, DigitalOcean, LLC: 2,896
- 47890, Unmanaged Ltd: 381
- 210006, Shereverov Marat Ahmedovich: 245
- 131427, AOHOAVIET: 210
- 209334, Modat B.V.: 166

**Source IP Addresses:**
- 170.64.230.118: 2,563
- 45.87.249.140: 245
- 103.53.231.159: 210
- 85.217.149.24: 133
- 129.212.184.194: 113

**Country to Port Mapping:**
- **Australia:**
  - 22: 512
- **Romania:**
  - 22: 39
  - 2188: 2
  - 2390: 2
  - 5032: 2
  - 5874: 2
- **Seychelles:**
  - 22: 49
  - 22443: 2
- **United States:**
  - 5902: 113
  - 1443: 84
  - 5903: 57
  - 5901: 54
  - 1388: 39
- **Vietnam:**
  - 22: 42
  - 23: 1

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- root: 94
- admin: 29
- user: 19
- ubuntu: 12
- user1: 12
- user2: 9
- user3: 8
- user4: 8
- 1admin: 7
- test: 7

**Passwords:**
- 123456: 118
- 123: 29
- 1234: 18
- 12345678: 13
- 111111: 10

**OS Distribution:**
- Windows NT kernel: 20,586
- Linux 2.2.x-3.x: 14,608
- Linux 2.2.x-3.x (barebone): 363
- Linux 2.2.x-3.x (no timestamps): 333
- Windows NT kernel 5.x: 141

**Hyper-aggressive IPs:**
- 170.64.230.118: 2,563 attacks
