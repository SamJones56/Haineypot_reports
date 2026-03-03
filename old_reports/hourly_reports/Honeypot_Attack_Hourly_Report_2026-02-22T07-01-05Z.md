# Honeypot Attack Report - 2026-02-22T07:00:13Z

Executive Summary:
- Over 3,000 attacks were observed in the past hour, with the majority originating from the United States and India.
- The most prominent attacker infrastructure is hosted on DigitalOcean, with a significant portion of attacking IPs identified as known attackers or mass scanners.
- Common attack vectors include SSH and VNC protocols, with "SURICATA SSH invalid banner" being the most frequent alert signature.
- A small number of CVEs were targeted, including CVE-2024-14007 and CVE-2025-55182.
- Brute-force attempts are prevalent, with common username/password combinations like "elastic," "ftptest," and "test1" for usernames, and "1234," "12345," and "123456" for passwords.
- The vast majority of attacking systems appear to be running Linux-based operating systems.

Detailed Analysis:

Total Attacks:
- 3082

Top Attacking Countries:
- United States: 1211
- India: 745
- Netherlands: 388
- Romania: 239
- Switzerland: 88

Notable IP Reputations:
- known attacker: 1273
- mass scanner: 164
- bot, crawler: 1

Common Alert Categories:
- Generic Protocol Command Decode: 556
- Misc activity: 452
- Misc Attack: 354
- Attempted Information Leak: 59
- Potentially Bad Traffic: 33

Alert Signatures:
- 2228000 - SURICATA SSH invalid banner: 241
- 2100560 - GPL INFO VNC server response: 222
- 2001984 - ET INFO SSH session in progress on Unusual Port: 117
- 2402000 - ET DROP Dshield Block Listed Source group 1: 102
- 2200003 - SURICATA IPv4 truncated packet: 83

ASN Information:
- 14061, DigitalOcean, LLC: 933
- 9498, BHARTI Airtel Ltd.: 370
- 47890, Unmanaged Ltd: 361
- 396982, Google LLC: 264
- 16509, Amazon.com, Inc.: 121

Source IP Addresses:
- 59.145.41.149: 370
- 143.110.179.223: 345
- 142.93.234.28: 320
- 129.212.184.194: 113
- 2.57.122.96: 90

Country to Port Mapping:
- India
  - 445: 370
  - 22: 69
  - 23: 12
- Netherlands
  - 22: 65
  - 1337: 20
  - 6037: 8
  - 9100: 8
  - 17001: 8
- Romania
  - 22: 40
  - 443: 3
  - 1886: 2
  - 2504: 2
  - 2526: 2
- Switzerland
  - 5435: 87
  - 5432: 1
- United States
  - 5902: 113
  - 5903: 58
  - 5901: 54
  - 80: 52
  - 23: 37

CVEs Exploited:
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2025-55182 CVE-2025-55182: 2

Usernames:
- elastic: 26
- ftptest: 26
- test1: 26
- www: 26
- root: 13
- gerrit: 12
- ubuntu: 9
- admin: 8
- solv: 8
- sol: 6

Passwords:
- 1234: 12
- 12345: 11
- 123456: 11
- 12345678: 10
- 1234567890: 10
- passw0rd: 10
- password: 10
- : 9
- 1: 9
- 1234567: 9

OS Distribution:
- Linux 2.2.x-3.x: 9243
- Linux 2.2.x-3.x (barebone): 389
- Windows NT kernel 5.x: 161
- Linux 2.2.x-3.x (no timestamps): 144
- Linux 3.11 and newer: 32

Hyper-aggressive IPs:
- 59.145.41.149: 370
- 143.110.179.223: 345
- 142.93.234.28: 320
- 129.212.184.194: 113
- 2.57.122.96: 90
