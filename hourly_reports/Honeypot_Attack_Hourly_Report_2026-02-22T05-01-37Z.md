# Honeypot Attack Report - 2026-02-22T05:00:15Z

## Executive Summary:
- **High-Volume Attack Activity:** A total of 3,256 attacks were observed in the past hour, indicating a significant level of malicious activity.
- **Geographic Concentration:** The majority of attacks originated from the United States (1,298), followed by India (622) and the Netherlands (362).
- **Dominant Aggressors:** A small number of IP addresses were responsible for a large portion of the attacks, with five IPs launching over 100 attacks each. The most aggressive IP was 142.93.234.28 with 324 attacks.
- **Common Tactics:** The most frequent alert categories were "Generic Protocol Command Decode" (658) and "Misc activity" (414), suggesting a high volume of reconnaissance and broad-spectrum attacks.
- **Exploitation Attempts:** The honeypot detected attempts to exploit several vulnerabilities, with CVE-2024-14007 being the most frequently targeted.
- **Credential Stuffing:** Brute-force attempts were common, with "root," "oracle," and "admin" being the most frequently used usernames, and simple passwords like "123456" and "password" being the most common.

## Detailed Analysis:

**Total Attacks:**
- 3256

**Top Attacking Countries:**
- United States: 1298
- India: 622
- Netherlands: 362
- Romania: 293
- Switzerland: 184

**Notable IP Reputations:**
- known attacker: 1320
- mass scanner: 136
- tor exit node: 1

**Common Alert Categories:**
- Generic Protocol Command Decode: 658
- Misc activity: 414
- Misc Attack: 318
- Attempted Information Leak: 52
- Potentially Bad Traffic: 20
- Detection of a Network Scan: 10
- Attempted Administrator Privilege Gain: 9
- Web Application Attack: 7
- Successful Administrator Privilege Gain: 6
- Not Suspicious Traffic: 2

**Alert Signatures:**
- 2228000 - SURICATA SSH invalid banner: 218
- 2100560 - GPL INFO VNC server response: 206
- 2200003 - SURICATA IPv4 truncated packet: 139
- 2200122 - SURICATA AF-PACKET truncated packet: 139
- 2001984 - ET INFO SSH session in progress on Unusual Port: 103
- 2402000 - ET DROP Dshield Block Listed Source group 1: 77
- 2001978 - ET INFO SSH session in progress on Expected Port: 67
- 2210048 - SURICATA STREAM reassembly sequence GAP -- missing packet(s): 50
- 2009582 - ET SCAN NMAP -sS window 1024: 40
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 31

**ASN Information:**
- 14061 - DigitalOcean, LLC: 897
- 47890 - Unmanaged Ltd: 419
- 9498 - BHARTI Airtel Ltd.: 307
- 20473 - The Constant Company, LLC: 274
- 396982 - Google LLC: 191
- 16509 - Amazon.com, Inc.: 188
- 51852 - Private Layer INC: 183
- 209334 - Modat B.V.: 89
- 6939 - Hurricane Electric LLC: 64
- 215925 - Vpsvault.host Ltd: 58

**Source IP Addresses:**
- 142.93.234.28: 324
- 143.110.179.223: 313
- 59.145.41.149: 307
- 144.202.31.88: 274
- 46.19.137.194: 183
- 2.57.122.210: 125
- 129.212.184.194: 103
- 193.32.162.151: 83
- 134.199.197.108: 51
- 165.245.138.210: 48

**Country to Port Mapping:**
- **Bulgaria**
  - 22: 12
- **Canada**
  - 8858: 3
  - 80: 2
  - 4953: 2
  - 8090: 2
  - 8728: 2
  - 45000: 2
  - 1111: 1
  - 1350: 1
  - 1391: 1
  - 1460: 1
- **Germany**
  - 22: 5
  - 1188: 4
  - 5874: 4
  - 6000: 4
  - 16277: 4
  - 50050: 3
  - 3827: 2
  - 5555: 2
  - 8545: 2
  - 8888: 2
- **India**
  - 445: 307
  - 22: 53
  - 23: 2
  - 2375: 2
  - 2376: 2
  - 2377: 2
  - 4243: 2
  - 4244: 2
  - 8265: 2
  - 8808: 2
- **Kazakhstan**
  - 445: 44
- **Netherlands**
  - 22: 61
  - 6036: 8
  - 17001: 8
  - 6037: 4
  - 17000: 4
  - 3306: 2
  - 80: 1
  - 2222: 1
  - 5006: 1
  - 5901: 1
- **Romania**
  - 22: 51
  - 4041: 2
  - 4170: 2
  - 4722: 2
  - 7909: 2
  - 13055: 2
  - 19646: 2
  - 21130: 2
  - 21982: 2
  - 23518: 2
- **Switzerland**
  - 5434: 182
  - 443: 1
  - 5432: 1
- **United Kingdom**
  - 5432: 3
  - 80: 2
  - 443: 2
  - 8196: 2
  - 9476: 2
  - 14440: 2
  - 45721: 2
  - 46375: 2
  - 47516: 2
  - 47694: 2
- **United States**
  - 2323: 127
  - 5902: 103
  - 23: 87
  - 5901: 52
  - 5903: 51
  - 8728: 49
  - 445: 33
  - 27017: 12
  - 80: 9
  - 2000: 9

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2023-26801 CVE-2023-26801: 2
- CVE-2018-10562 CVE-2018-10561: 1
- CVE-2021-3449 CVE-2021-3449: 1
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- root: 57
- oracle: 23
- admin: 21
- test: 19
- sol: 11
- postgres: 10
- mysql: 7
- nexus: 6
- user: 5
- solana: 4

**Passwords:**
- 123456: 12
- 1: 11
- password: 10
- 12345: 9
- 12345678: 9
- 12: 8
- 123: 8
- 1234: 8
- 123456789: 7
- passw0rd: 7

**OS Distribution:**
- Linux 2.2.x-3.x: 6614
- Windows 7 or 8: 358
- Linux 2.2.x-3.x (barebone): 319
- Windows NT kernel 5.x: 132
- Linux 2.2.x-3.x (no timestamps): 43
- Windows NT kernel: 23
- Linux 3.11 and newer: 20
- Mac OS X: 18
- Linux 3.1-3.10: 14
- Linux 3.x: 5

**Hyper-aggressive IPs:**
- 142.93.234.28: 324
- 143.110.179.223: 313
- 59.145.41.149: 307
- 144.202.31.88: 274
- 46.19.137.194: 183
- 2.57.122.210: 125
- 129.212.184.194: 103
