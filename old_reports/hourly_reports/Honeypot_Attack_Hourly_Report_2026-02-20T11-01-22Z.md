# Honeypot Attack Report - 2026-02-20T11:00:22Z

Executive Summary:
- The network observed a high volume of attacks, totaling 8,432 in the last hour.
- A significant portion of attacks originated from Azerbaijan (3,108) and Brazil (1,350), with a single IP from each country being responsible for the majority of their respective country's attack volume.
- The most prevalent alert signature was "GPL INFO VNC server response" with 2,288 instances, indicating a focus on VNC services.
- Attackers primarily targeted port 445, with a high concentration of this activity from Azerbaijan and Brazil.
- A large number of attacking IPs were fingerprinted as running Windows NT kernel, while a slightly smaller number were identified as Linux 2.2.x-3.x.
- There were several hyper-aggressive IPs, with 213.154.18.82 from Azerbaijan being the most aggressive, accounting for 3,108 attacks alone.

Detailed Analysis:

Total Attacks:
- 8432

Top Attacking Countries:
- Azerbaijan: 3108
- Brazil: 1350
- Germany: 1035
- United Kingdom: 655
- United States: 591

Notable IP Reputations:
- known attacker: 1069
- mass scanner: 212

Common Alert Categories:
- Misc activity: 2487
- Generic Protocol Command Decode: 661
- Misc Attack: 424
- Attempted Information Leak: 148
- Attempted Administrator Privilege Gain: 49
- Potentially Bad Traffic: 28
- Detection of a Network Scan: 5
- Not Suspicious Traffic: 4
- Web Application Attack: 2
- access to a potentially vulnerable web application: 2

Alert Signatures:
- 2100560, GPL INFO VNC server response: 2288
- 2200003, SURICATA IPv4 truncated packet: 238
- 2200122, SURICATA AF-PACKET truncated packet: 238
- 2402000, ET DROP Dshield Block Listed Source group 1: 105
- 2023753, ET SCAN MS Terminal Server Traffic on Non-standard Port: 98
- 2001978, ET INFO SSH session in progress on Expected Port: 89
- 2038967, ET INFO SSH-2.0-Go version string Observed in Network Traffic: 82
- 2009582, ET SCAN NMAP -sS window 1024: 43
- 2034857, ET HUNTING RDP Authentication Bypass Attempt: 43
- 2210061, SURICATA STREAM spurious retransmission: 33

ASN Information:
- 28787, Aztelekom LLC: 3108
- 14061, DigitalOcean, LLC: 2142
- 27699, TELEFONICA BRASIL S.A: 1348
- 8075, Microsoft Corporation: 381
- 47890, Unmanaged Ltd: 181
- 211860, Nerushenko Vyacheslav Nikolaevich: 168
- 396982, Google LLC: 149
- 16509, Amazon.com, Inc.: 133
- 213412, ONYPHE SAS: 112
- 6939, Hurricane Electric LLC: 72

Source IP Addresses:
- 213.154.18.82: 3108
- 201.1.161.225: 1348
- 167.99.218.227: 540
- 206.189.61.203: 540
- 144.126.205.38: 536
- 206.81.21.204: 461
- 4.145.113.4: 352
- 82.147.85.136: 168
- 2.57.122.208: 105
- 103.53.231.159: 67

Country to Port Mapping:
- Azerbaijan
  - 445: 3108
- Brazil
  - 445: 1348
  - 80: 1
  - 2222: 1
- Germany
  - 22: 197
  - 9496: 7
  - 9080: 4
  - 12350: 4
  - 61665: 4
- United Kingdom
  - 22: 104
  - 5400: 7
  - 1445: 2
  - 1980: 2
  - 2016: 2
- United States
  - 27017: 33
  - 6379: 27
  - 9000: 12
  - 22: 11
  - 49153: 10

CVEs Exploited:
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2020-2551 CVE-2020-2551 CVE-2020-2551: 2
- CVE-2025-55182 CVE-2025-55182: 2
- CVE-2019-11500 CVE-2019-11500: 1

Usernames:
- root: 70
- admin: 58
- ubuntu: 57
- test: 49
- user: 44
- oracle: 20
- postgres: 20
- dev: 13
- developer: 13
- docker: 13

Passwords:
- 123456: 30
- password: 28
- 123456789: 23
- 12345: 21
- welcome: 16
- admin123: 14
- 1234567: 13
- 12345678: 12
- abc123: 12
- password1: 12

OS Distribution:
- Windows NT kernel: 17051
- Linux 2.2.x-3.x: 16057
- Windows NT kernel 5.x: 9718
- Windows 7 or 8: 4457
- Linux 2.2.x-3.x (barebone): 231
- Linux 2.2.x-3.x (no timestamps): 84
- Mac OS X: 37
- Linux 3.11 and newer: 24
- Linux 3.1-3.10: 21
- Linux 2.4.x-2.6.x: 1

Hyper-aggressive IPs:
- 213.154.18.82: 3108
- 201.1.161.225: 1348
- 167.99.218.227: 540
- 206.189.61.203: 540
- 144.126.205.38: 536
