
# Honeypot Attack Report - 2026-02-22T21:00:15Z

## Executive Summary
- **High Attack Volume:** A total of 6,699 attacks were observed in the past hour, with the majority originating from the United States and the United Kingdom.
- **Dominant Attacker Infrastructure:** DigitalOcean, LLC infrastructure was the source of a significant portion of the attacks, accounting for 4,584 incidents.
- **Common Attack Vectors:** The most frequent attack categories were 'Misc activity' and 'Generic Protocol Command Decode', indicating a high volume of reconnaissance and non-specific threats.
- **Credential Stuffing:** Brute-force attempts were prevalent, with common usernames like 'user', 'git', and 'root' being targeted with simple passwords such as '123456' and 'password'.
- **Hyper-Aggressive IPs:** Several IP addresses were identified as hyper-aggressive, with the top IP, 161.35.39.52, responsible for 655 attacks.
- **Vulnerability Scanning:** The honeypot detected scanning for multiple vulnerabilities, including CVE-2024-14007 and CVE-2023-46604.

## Detailed Analysis

### Total Attacks
- **Total:** 6,699

### Top Attacking Countries
- United States: 2,408
- United Kingdom: 2,180
- Germany: 822
- India: 391
- Romania: 201

### Notable IP Reputations
- known attacker: 1,671
- mass scanner: 65
- bot, crawler: 3

### Common Alert Categories
- Misc activity: 584
- Generic Protocol Command Decode: 541
- Misc Attack: 233
- Attempted Information Leak: 93
- Attempted Administrator Privilege Gain: 18
- Web Application Attack: 11
- Potentially Bad Traffic: 10
- Detection of a Network Scan: 4
- Malware Command and Control Activity Detected: 2
- Not Suspicious Traffic: 2

### Alert Signatures
- 2100560 - GPL INFO VNC server response: 222
- 2228000 - SURICATA SSH invalid banner: 184
- 2001978 - ET INFO SSH session in progress on Expected Port: 160
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 98
- 2200003 - SURICATA IPv4 truncated packet: 90
- 2200122 - SURICATA AF-PACKET truncated packet: 90
- 2001984 - ET INFO SSH session in progress on Unusual Port: 88
- 2402000 - ET DROP Dshield Block Listed Source group 1: 65
- 2009582 - ET SCAN NMAP -sS window 1024: 49
- 2210048 - SURICATA STREAM reassembly sequence GAP -- missing packet(s): 36

### ASN Information
- 14061 - DigitalOcean, LLC: 4,584
- 47890 - Unmanaged Ltd: 349
- 210006 - Shereverov Marat Ahmedovich: 325
- 202425 - IP Volume inc: 237
- 396982 - Google LLC: 224
- 131427 - AOHOAVIET: 135
- 63949 - Akamai Connected Cloud: 124
- 51852 - Private Layer INC: 117
- 135377 - UCLOUD INFORMATION TECHNOLOGY HK LIMITED: 68
- 211736 - FOP Dmytro Nedilskyi: 50

### Source IP Addresses
- 161.35.39.52: 655
- 134.122.118.217: 543
- 134.122.22.110: 525
- 167.172.56.108: 524
- 142.93.39.124: 495
- 159.65.61.59: 489
- 206.81.25.52: 450
- 159.65.153.107: 391
- 178.20.210.32: 325
- 107.170.92.75: 253

### Country to Port Mapping
- **United States:**
  - 22: 270
  - 5902: 123
  - 1024: 117
  - 5903: 57
  - 5901: 54
  - 1025: 26
  - 6467: 18
  - 1800: 17
  - 8728: 14
  - 45270: 13
- **United Kingdom:**
  - 22: 434
  - 80: 4
  - 443: 2
  - 8000: 2
  - 3000: 1
  - 5081: 1
  - 8092: 1
  - 9192: 1
  - 13818: 1
  - 28888: 1
- **Germany:**
  - 22: 156
  - 8231: 4
  - 8803: 4
  - 33322: 4
  - 46640: 4
  - 49639: 4
  - 12520: 3
  - 1990: 2
  - 7777: 2
  - 9090: 2
- **India:**
  - 22: 75
- **Romania:**
  - 22: 29
  - 5748: 2
  - 14030: 2
  - 17874: 2
  - 19955: 2
  - 23881: 2
  - 24401: 2
  - 27477: 2
  - 27842: 2
  - 28755: 2
- **Hong Kong:**
    - 27017: 13
    - 49152: 11
    - 1024: 9
    - 80: 1
    - 9762: 1
    - 10829: 1
    - 20087: 1
- **Netherlands:**
    - 443: 97
    - 27017: 21
    - 6037: 16
    - 6036: 8
    - 17001: 8
    - 80: 3
    - 81: 2
    - 8545: 2
    - 18789: 2
    - 25565: 2
- **Switzerland:**
    - 5433: 116
    - 5432: 1
- **Ukraine:**
    - 22: 8
    - 1111: 4
    - 4443: 4
    - 9443: 4
    - 11443: 2
    - 443: 1
- **Vietnam:**
    - 22: 27
    - 2375: 3

### CVEs Exploited
- CVE-2024-14007 CVE-2024-14007: 5
- CVE-2023-46604 CVE-2023-46604 CVE-2023-46604: 2
- CVE-2025-55182 CVE-2025-55182: 2
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2021-3449 CVE-2021-3449: 1

### Usernames
- user: 108
- git: 95
- root: 93
- hadoop: 75
- admin: 61
- oracle: 55
- ubuntu: 49
- test: 47
- nginx: 36
- pi: 36

### Passwords
- 123456: 61
- password: 50
- 123: 39
- 1234: 38
- 12345: 35
- 123456789: 32
- passw0rd: 32
- qwerty: 32
- 12345678: 30
- letmein: 23

### OS Distribution
- Linux 2.2.x-3.x: 15,621
- Windows NT kernel: 2,206
- Linux 2.2.x-3.x (barebone): 329
- Windows NT kernel 5.x: 75
- Linux 2.2.x-3.x (no timestamps): 479
- Linux 3.11 and newer: 36
- Mac OS X: 16
- Linux 3.1-3.10: 2
- Linux 3.x: 1
- Nintendo 3DS: 2

### Hyper-aggressive IPs
- 161.35.39.52: 655
- 134.122.118.217: 543
- 134.122.22.110: 525
- 167.172.56.108: 524
- 142.93.39.124: 495
- 159.65.61.59: 489
- 206.81.25.52: 450
- 159.65.153.107: 391
- 178.20.210.32: 325
- 107.170.92.75: 253
