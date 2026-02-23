
# Honeypot Attack Report - 2026-02-23T17:00:26Z

## Executive Summary:
- This report covers 3265 attacks detected over the last hour.
- The majority of attacks originated from the United States (1099), with significant activity also observed from Germany (684) and the United Kingdom (355).
- A large portion of attacking IPs (1288) are identified as known attackers.
- Dominant attack vectors include "Generic Protocol Command Decode" (398) and "Misc activity" (392).
- Brute-force attempts are prevalent, with "root" (87) and "admin" (37) being the most targeted usernames.
- The most frequent alert signature is "GPL INFO VNC server response" (220).

## Detailed Analysis:

### Total Attacks:
- 3265

### Top Attacking Countries:
- United States: 1099
- Germany: 684
- United Kingdom: 355
- Canada: 270
- India: 200

### Notable IP Reputations:
- known attacker: 1288
- mass scanner: 192
- bot, crawler: 57

### Common Alert Categories:
- Generic Protocol Command Decode: 398
- Misc activity: 392
- Misc Attack: 362
- Attempted Information Leak: 86
- Attempted Administrator Privilege Gain: 13

### Alert Signatures:
- 2100560, GPL INFO VNC server response: 220
- 2228000, SURICATA SSH invalid banner: 186
- 2402000, ET DROP Dshield Block Listed Source group 1: 122
- 2001984, ET INFO SSH session in progress on Unusual Port: 81
- 2009582, ET SCAN NMAP -sS window 1024: 59

### ASN Information:
- 14061, DigitalOcean, LLC: 1376
- 209334, Modat B.V.: 264
- 47890, Unmanaged Ltd: 226
- 202425, IP Volume inc: 203
- 137120, Nas Internet Services Private Limited: 200

### Source IP Addresses:
- 165.22.127.188: 230
- 167.172.99.91: 220
- 164.92.199.63: 218
- 103.206.100.26: 200
- 46.101.103.139: 195

### Country to Port Mapping:
- Canada:
  - 8728: 6
  - 1989: 2
  - 3299: 2
  - 3409: 2
  - 3732: 2
- Germany:
  - 22: 98
  - 1234: 23
  - 9443: 7
  - 2913: 4
  - 6150: 4
- India:
  - 23: 100
- United Kingdom:
  - 80: 55
  - 22: 46
  - 23: 23
  - 18789: 7
  - 4444: 3
- United States:
  - 5902: 112
  - 6000: 82
  - 6001: 80
  - 5903: 57
  - 5901: 55

### CVEs Exploited:
- CVE-2021-3449 CVE-2021-3449
- CVE-2024-14007 CVE-2024-14007
- CVE-2024-4577 CVE-2002-0953
- CVE-2024-4577 CVE-2024-4577
- CVE-2002-0013 CVE-2002-0012

### Usernames:
- root: 87
- admin: 37
- administrator: 9
- ftpuser: 9
- pi: 9
- postgres: 9
- centos: 8
- debian: 8
- fedora: 8
- mysql: 7

### Passwords:
- 123456: 19
- 12345678: 19
- 1234: 14
- 123: 13
- 12345: 12

### OS Distribution:
- Linux 2.2.x-3.x: 16393
- Windows NT kernel: 18787
- Linux 2.2.x-3.x (barebone): 292
- Windows NT kernel 5.x: 147
- Linux 2.2.x-3.x (no timestamps): 450

### Hyper-aggressive IPs:
- 165.22.127.188: 230
- 167.172.99.91: 220
- 164.92.199.63: 218
- 103.206.100.26: 200
- 46.101.103.139: 195
