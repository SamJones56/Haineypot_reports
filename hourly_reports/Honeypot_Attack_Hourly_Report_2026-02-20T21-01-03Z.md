
# Honeypot Attack Report - 2026-02-20T21:00:22Z

Executive Summary:
- Over 9,600 attacks were observed in the last hour.
- The majority of attacks originated from Paraguay, with a single IP address (45.175.157.3) responsible for over 6,100 attacks.
- "Generic Protocol Command Decode" was the most common alert category.
- Brute-force attempts were prevalent, with "root" being the most common username.
- The dominant attacking OS was identified as Windows NT kernel.
- Two CVEs were detected: CVE-2024-14007 and CVE-2006-2369.

Detailed Analysis:

Total Attacks:
- 9674

Top Attacking Countries:
- Paraguay: 6166
- Australia: 1075
- United States: 944
- Germany: 451
- Romania: 277

Notable IP Reputations:
- known attacker: 2087
- mass scanner: 121
- tor exit node: 6

Common Alert Categories:
- Generic Protocol Command Decode: 834
- Misc activity: 511
- Misc Attack: 297
- Attempted Information Leak: 59
- Potentially Bad Traffic: 9
- Attempted Administrator Privilege Gain: 4
- Detection of a Network Scan: 3
- Malware Command and Control Activity Detected: 2
- : 1

Alert Signatures:
- 2200003 - SURICATA IPv4 truncated packet: 264
- 2200122 - SURICATA AF-PACKET truncated packet: 264
- 2100560 - GPL INFO VNC server response: 258
- 2228000 - SURICATA SSH invalid banner: 181
- 2001984 - ET INFO SSH session in progress on Unusual Port: 104
- 2001978 - ET INFO SSH session in progress on Expected Port: 87
- 2402000 - ET DROP Dshield Block Listed Source group 1: 74
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 56
- 2009582 - ET SCAN NMAP -sS window 1024: 42
- 2210048 - SURICATA STREAM reassembly sequence GAP -- missing packet(s): 33

ASN Information:
- 267837 - Vicente Sosa Peralta: 6166
- 14061 - DigitalOcean, LLC: 1158
- 47890 - Unmanaged Ltd: 391
- 210006 - Shereverov Marat Ahmedovich: 390
- 208885 - Noyobzoda Faridduni Saidilhom: 247
- 202425 - IP Volume inc: 241
- 396982 - Google LLC: 188
- 4764 - Aussie Broadband: 144
- 135377 - UCLOUD INFORMATION TECHNOLOGY HK LIMITED: 74
- 48090 - Techoff Srv Limited: 73

Source IP Addresses:
- 45.175.157.3: 6166
- 170.64.183.111: 607
- 178.20.210.32: 390
- 134.199.171.153: 324
- 86.54.24.29: 247
- 120.88.124.11: 144
- 2.57.122.210: 135
- 159.203.72.187: 78
- 185.242.226.39: 68
- 188.166.100.4: 63

Country to Port Mapping:
- Australia:
  - 22: 179
  - 37777: 144
- Germany:
  - 22: 80
  - 80: 11
  - 9100: 8
  - 1117: 4
  - 9209: 4
- Paraguay:
  - 22: 1233
  - 2222: 1
- Romania:
  - 22: 46
  - 3000: 7
  - 3279: 2
  - 7756: 2
  - 9016: 2
- United States:
  - 22: 24
  - 1025: 18
  - 2323: 14
  - 8728: 14
  - 443: 10

CVEs Exploited:
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2006-2369: 1

Usernames:
- root: 1306
- admin: 35
- postgres: 34
- sol: 20
- oracle: 12
- ubuntu: 12
- solana: 11
- user: 11
- sshd: 8
- www-data: 7

Passwords:
- password: 20
- 123456: 19
- pfsense: 15
- 1234: 13
- 123: 12
- www-data: 7
- 12345678: 5
- admin: 5
- p@ssw0rd: 5
- zyad1234: 5

OS Distribution:
- Linux 2.2.x-3.x: 12272
- Windows NT kernel: 16853
- Linux 2.2.x-3.x (barebone): 354
- Windows NT kernel 5.x: 78
- Linux 2.2.x-3.x (no timestamps): 321
- Linux 3.11 and newer: 173
- Mac OS X: 15
- Linux 3.1-3.10: 27
- Linux 2.4.x: 2
- Windows XP: 2

Hyper-aggressive IPs:
- 45.175.157.3: 6166

