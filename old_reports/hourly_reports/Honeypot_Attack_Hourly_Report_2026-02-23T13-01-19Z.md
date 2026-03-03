# Honeypot Attack Report - 2026-02-23T13:00:25Z

Executive Summary:
- The honeypot registered 4,808 attacks in the last hour.
- The United States was the top attacking country with 1,206 attacks.
- The most active ASN was DigitalOcean, LLC (14061) with 2,844 attacks.
- The most active IP address was 167.71.230.193 with 525 attacks.
- The most common alert signature was "GPL INFO VNC server response" (2100560) with 254 hits.
- The most common username and password combination was `root` and `qwerty`.

Detailed Analysis:

Total Attacks:
- 4808

Top Attacking Countries:
- United States: 1206
- Canada: 810
- Germany: 700
- India: 572
- United Kingdom: 379

Notable IP Reputations:
- known attacker: 1899
- mass scanner: 195

Common Alert Categories:
- Misc activity: 567
- Generic Protocol Command Decode: 453
- Misc Attack: 407
- Attempted Information Leak: 131
- Attempted Administrator Privilege Gain: 26
- Potentially Bad Traffic: 26
- access to a potentially vulnerable web application: 17
- Web Application Attack: 12
- Detection of a Denial of Service Attack: 2
- A Network Trojan was detected: 1

Alert Signatures:
- 2100560 - GPL INFO VNC server response: 254
- 2228000 - SURICATA SSH invalid banner: 175
- 2402000 - ET DROP Dshield Block Listed Source group 1: 131
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 120
- 2001978 - ET INFO SSH session in progress on Expected Port: 105
- 2001984 - ET INFO SSH session in progress on Unusual Port: 82
- 2009582 - ET SCAN NMAP -sS window 1024: 60
- 2200003 - SURICATA IPv4 truncated packet: 60
- 2200122 - SURICATA AF-PACKET truncated packet: 60
- 2023753 - ET SCAN MS Terminal Server Traffic on Non-standard Port: 48

ASN Information:
- 14061 - DigitalOcean, LLC: 2844
- 209334 - Modat B.V.: 390
- 47890 - Unmanaged Ltd: 310
- 131427 - AOHOAVIET: 170
- 51852 - Private Layer INC: 124
- 16509 - Amazon.com, Inc.: 111
- 213412 - ONYPHE SAS: 110
- 396982 - Google LLC: 102
- 63949 - Akamai Connected Cloud: 60
- 215925 - Vpsvault.host Ltd: 56

Source IP Addresses:
- 167.71.230.193: 525
- 161.35.220.52: 445
- 159.65.81.102: 365
- 159.203.4.252: 216
- 134.199.156.189: 202
- 138.197.136.45: 193
- 103.53.231.159: 170
- 46.19.137.194: 124
- 129.212.184.194: 114
- 64.227.125.176: 105

Country to Port Mapping:
- Canada
  - 22: 75
  - 8728: 8
  - 3627: 3
  - 3803: 3
  - 4547: 3
- Germany
  - 22: 127
  - 10250: 18
  - 25: 7
  - 8712: 4
  - 60007: 4
- India
  - 22: 114
  - 8081: 2
- United Kingdom
  - 22: 73
  - 80: 3
  - 4444: 3
  - 4117: 2
  - 7700: 2
- United States
  - 5901: 138
  - 5902: 115
  - 5903: 60
  - 22: 45
  - 5672: 18

CVEs Exploited:
- CVE-2025-55182 CVE-2025-55182: 12
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2023-46604 CVE-2023-46604 CVE-2023-46604: 2
- CVE-2002-1149: 1

Usernames:
- root: 92
- guest: 42
- debian: 30
- user: 25
- postgres: 23
- dev: 22
- developer: 22
- elastic: 22
- elasticsearch: 22
- es: 22

Passwords:
- qwerty: 30
- 123456: 28
- 654321: 23
- 123qwe: 21
- 4321: 18
- 54321: 18
- 123qwerty: 17
- wasd: 17
- 123: 16
- 12345678: 15

OS Distribution:
- Linux 2.2.x-3.x: 15596
- Windows NT kernel: 18947
- Linux 2.2.x-3.x (barebone): 217
- Windows NT kernel 5.x: 189
- Linux 2.2.x-3.x (no timestamps): 148
- Linux 3.11 and newer: 44
- Windows 7 or 8: 37
- Mac OS X: 17
- Windows XP: 3
- Nintendo 3DS: 2

Hyper-aggressive IPs:
- 167.71.230.193: 525
- 161.35.220.52: 445
- 159.65.81.102: 365
- 159.203.4.252: 216
- 134.199.156.189: 202
- 138.197.136.45: 193
- 103.53.231.159: 170
- 46.19.137.194: 124
- 129.212.184.194: 114
- 64.227.125.176: 105
