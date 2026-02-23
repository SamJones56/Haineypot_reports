# Honeypot Attack Report - 2026-02-23T18:00:29Z

Executive Summary:
- Over 2,800 attacks were observed in the past hour, with the United States, Germany, and the Netherlands being the primary sources of origin.
- The most prominent attacker, IP 167.172.99.91, was responsible for 370 attacks. The majority of attacking IPs are associated with DigitalOcean hosting.
- The most common alert category was 'Generic Protocol Command Decode', indicating a high volume of reconnaissance and protocol-level probing.
- The VNC (Virtual Network Computing) protocol was a primary target, with the 'GPL INFO VNC server response' signature being the most frequently triggered alert.
- Brute-force attempts were common, with simple usernames like 'ubuntu', 'admin', and 'test' being paired with weak passwords such as '123456'.
- The most frequently observed operating systems were Windows NT Kernel and Linux 2.2.x-3.x, suggesting that attackers are using a mix of older and newer systems.

Detailed Analysis:

Total Attacks:
- 2809

Top Attacking Countries:
- United States: 1226
- Germany: 559
- Netherlands: 376
- Vietnam: 205
- Ireland: 92

Notable IP Reputations:
- known attacker: 1069
- mass scanner: 168

Common Alert Categories:
- Generic Protocol Command Decode: 548
- Misc Attack: 404
- Misc activity: 394
- Attempted Information Leak: 75
- Potentially Bad Traffic: 23
- Attempted Administrator Privilege Gain: 4
- Detection of a Network Scan: 3
- Detection of a Denial of Service Attack: 1
- Malware Command and Control Activity Detected: 1

Alert Signatures:
- 2100560 - GPL INFO VNC server response: 214
- 2228000 - SURICATA SSH invalid banner: 191
- 2200003 - SURICATA IPv4 truncated packet: 114
- 2200122 - SURICATA AF-PACKET truncated packet: 114
- 2402000 - ET DROP Dshield Block Listed Source group 1: 112
- 2001984 - ET INFO SSH session in progress on Unusual Port: 90
- 2009582 - ET SCAN NMAP -sS window 1024: 59
- 2001978 - ET INFO SSH session in progress on Expected Port: 47
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 35
- 2210061 - SURICATA STREAM spurious retransmission: 18

ASN Information:
- 14061 - DigitalOcean, LLC: 1089
- 8075 - Microsoft Corporation: 303
- 47890 - Unmanaged Ltd: 209
- 202425 - IP Volume inc: 209
- 131427 - AOHOAVIET: 205
- 213412 - ONYPHE SAS: 98
- 16509 - Amazon.com, Inc.: 96
- 63949 - Akamai Connected Cloud: 86
- 396982 - Google LLC: 73
- 9541 - Cyber Internet Services Pvt Ltd.: 48

Source IP Addresses:
- 167.172.99.91: 370
- 167.99.39.172: 304
- 103.53.231.159: 205
- 20.114.221.114: 179
- 129.212.184.194: 108
- 20.223.240.16: 92
- 46.101.103.139: 83
- 185.242.226.46: 77
- 164.92.199.63: 66
- 134.199.197.108: 57

Country to Port Mapping:
- Germany
  - 22: 102
  - 8500: 14
  - 18789: 7
  - 1090: 4
  - 1818: 4
- Ireland
  - 80: 92
- Netherlands
  - 22: 60
  - 80: 10
  - 6036: 8
  - 17000: 8
  - 8728: 7
- United States
  - 80: 183
  - 5902: 108
  - 1291: 78
  - 5903: 58
  - 5901: 54
- Vietnam
  - 22: 41

CVEs Exploited:
- CVE-2002-0013 CVE-2002-0012: 3
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2021-3449 CVE-2021-3449: 1

Usernames:
- ubuntu: 44
- admin: 40
- test: 34
- centos: 30
- guest: 24
- ubnt: 10
- user: 10
- postgres: 9
- root: 9
- help: 8

Passwords:
- 123456: 24
- 123: 20
- 1234: 20
- 12345678: 19
- password: 11
- 12345: 9
- 123456789: 9
- 1q2w3e4r: 9
- 000000: 8
- 123123: 8

OS Distribution:
- Windows NT kernel: 20059
- Linux 2.2.x-3.x: 16704
- Linux 2.2.x-3.x (no timestamps): 415
- Linux 2.2.x-3.x (barebone): 382
- Windows NT kernel 5.x: 173
- Linux 3.11 and newer: 40
- Linux 3.1-3.10: 25
- Mac OS X: 17
- Windows 7 or 8: 8
- Linux 2.4.x-2.6.x: 6

Hyper-aggressive IPs:
- 167.172.99.91: 370
- 167.99.39.172: 304
- 103.53.231.159: 205
- 20.114.221.114: 179
- 129.212.184.194: 108
