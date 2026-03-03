# Honeypot Attack Report - 2026-02-23T18:15:32Z

## Executive Summary:
- Over the last 6 hours, 32,890 attacks were observed, with the United States being the most prominent source country, accounting for nearly half of all attacks.
- The most aggressive IP, 165.245.134.97, was responsible for 5,829 attacks, originating from the DigitalOcean (AS14061) network.
- A significant portion of attackers (16,214 events) were associated with IPs already flagged as 'known attackers'.
- The most frequent alert signature was 'ET INFO CURL User Agent', suggesting a high volume of automated scanning and reconnaissance activities.
- Brute-force attempts remain a common tactic, with 'root' and 'admin' being the most targeted usernames and '123456' the most common password.
- Exploitation of older vulnerabilities like CVE-2002-1149 was observed alongside more recent ones.

## Detailed Analysis:

### Total Attacks:
- 32,890

### Top Attacking Countries:
- United States: 15,255
- France: 2,553
- Netherlands: 2,455
- Germany: 2,255
- Canada: 1,663

### Notable IP Reputations:
- known attacker: 16,214
- mass scanner: 1,060
- bot, crawler: 58

### Common Alert Categories:
- Generic Protocol Command Decode: 5,252
- Attempted Information Leak: 3,827
- Misc activity: 3,487
- Misc Attack: 2,222
- Potentially Bad Traffic: 87

### Alert Signatures:
- ID: 2002824, Signature: ET INFO CURL User Agent, Count: 2,315
- ID: 2200003, Signature: SURICATA IPv4 truncated packet, Count: 1,409
- ID: 2200122, Signature: SURICATA AF-PACKET truncated packet, Count: 1,409
- ID: 2100560, Signature: GPL INFO VNC server response, Count: 1,352
- ID: 2228000, Signature: SURICATA SSH invalid banner, Count: 1,116

### ASN Information:
- ASN: 14061, Organization: DigitalOcean, LLC, Count: 18,086
- ASN: 211590, Organization: Bucklog SARL, Count: 2,268
- ASN: 46844, Organization: Sharktech, Count: 1,874
- ASN: 47890, Organization: Unmanaged Ltd, Count: 1,696
- ASN: 131427, Organization: AOHOAVIET, Count: 1,070

### Source IP Addresses:
- 165.245.134.97: 5,829
- 64.32.31.2: 1,874
- 185.177.72.49: 1,772
- 103.53.231.159: 1,070
- 164.92.222.100: 702

### Country to Port Mapping:
- **Canada**:
  - 22: 162
  - 8728: 48
  - 21327: 4
  - 1231: 3
  - 1982: 3
- **France**:
  - 80: 2,268
  - 3128: 15
  - 9002: 4
  - 9004: 4
  - 9011: 4
- **Germany**:
  - 22: 340
  - 1234: 38
  - 10250: 32
  - 2379: 28
  - 4891: 28
- **Netherlands**:
  - 22: 379
  - 443: 103
  - 9100: 45
  - 6036: 32
  - 6037: 32
- **United States**:
  - 1080: 1,874
  - 22: 1,431
  - 5902: 674
  - 5901: 408
  - 5903: 348

### CVEs Exploited:
- CVE-2025-55182 CVE-2025-55182: 37
- CVE-2002-1149: 28
- CVE-2024-14007 CVE-2024-14007: 21
- CVE-2021-1499 CVE-2021-1499: 17
- CVE-2021-3449 CVE-2021-3449: 9

### Usernames:
- root: 845
- admin: 322
- ubuntu: 152
- test: 145
- postgres: 117
- user: 105
- oracle: 86
- guest: 85
- centos: 82
- dspace: 29

### Passwords:
- 123456: 514
- 123: 170
- 12345678: 136
- 1234: 135
- password: 115

### OS Distribution:
- Windows NT kernel: 115,755
- Linux 2.2.x-3.x: 98,648
- Linux 2.2.x-3.x (no timestamps): 1,751
- Linux 2.2.x-3.x (barebone): 1,729
- Windows NT kernel 5.x: 989

### Hyper-aggressive IPs:
- 165.245.134.97: 5,829
- 64.32.31.2: 1,874
- 185.177.72.49: 1,772
- 103.53.231.159: 1,070
