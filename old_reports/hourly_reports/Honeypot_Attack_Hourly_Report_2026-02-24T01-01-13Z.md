
# Honeypot Attack Report - 2026-02-24T01:00:24Z

## Executive Summary:
- A total of 3223 attacks were observed in the last hour.
- The United States and Russia were the top attacking countries, accounting for a significant portion of the attacks.
- The most prominent attacker IP was 82.147.84.74 with 873 attacks, associated with AS211860 (Nerushenko Vyacheslav Nikolaevich).
- "Generic Protocol Command Decode" was the most frequent alert category.
- Common usernames and passwords like "root", "admin", and "123456" were frequently used in brute-force attempts.
- Exploitation of CVE-2024-14007 was observed.

## Detailed Analysis:

### Total Attacks:
- 3223

### Top Attacking Countries:
- United States: 1165
- Russia: 891
- Seychelles: 544
- Romania: 169
- Netherlands: 146

### Notable IP Reputations:
- known attacker: 1512
- mass scanner: 104
- bot, crawler: 7

### Common Alert Categories:
- Generic Protocol Command Decode: 886
- Misc activity: 363
- Misc Attack: 305
- Attempted Information Leak: 66
- Detection of a Network Scan: 19

### Alert Signatures:
- 2200003 - SURICATA IPv4 truncated packet: 248
- 2200122 - SURICATA AF-PACKET truncated packet: 248
- 2100560 - GPL INFO VNC server response: 218
- 2210048 - SURICATA STREAM reassembly sequence GAP -- missing packet(s): 164
- 2228000 - SURICATA SSH invalid banner: 159

### ASN Information:
- AS211860 - Nerushenko Vyacheslav Nikolaevich: 873
- AS210006 - Shereverov Marat Ahmedovich: 535
- AS14061 - DigitalOcean, LLC: 405
- AS47890 - Unmanaged Ltd: 281
- AS202425 - IP Volume inc: 187

### Source IP Addresses:
- 82.147.84.74: 873
- 45.87.249.140: 535
- 129.212.184.194: 112
- 2.57.122.208: 107
- 4.255.221.217: 102

### Country to Port Mapping:
- Netherlands
  - 17001: 16
  - 3478: 8
  - 6036: 8
  - 6037: 8
  - 9100: 8
- Romania
  - 22: 26
  - 4738: 2
  - 7640: 2
  - 11087: 2
  - 14414: 2
- Russia
  - 4786: 11
  - 3196: 4
  - 1025: 3
  - 9006: 3
  - 23: 2
- Seychelles
  - 22: 107
  - 37777: 9
- United States
  - 5902: 112
  - 80: 107
  - 1459: 78
  - 5903: 57
  - 5901: 55

### CVEs Exploited:
- CVE-2024-14007 CVE-2024-14007: 6
- CVE-2019-11500 CVE-2019-11500: 2

### Usernames:
- root: 37
- admin: 32
- user: 13
- ubuntu: 5
- pi: 3
- postgres: 3
- sol: 3
- test: 3
- Admin: 2
- internet: 2

### Passwords:
- admin: 9
- 123456: 8
- 123: 3
- 1234: 3
- 12345: 3

### OS Distribution:
- Windows NT kernel: 18568
- Linux 2.2.x-3.x: 17801
- Linux 3.1-3.10: 2535
- Linux 3.11 and newer: 1690
- Linux 3.x: 867

### Hyper-aggressive IPs:
- 82.147.84.74: 873
- 45.87.249.140: 535
