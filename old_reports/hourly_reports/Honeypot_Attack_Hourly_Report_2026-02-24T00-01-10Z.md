# Honeypot Attack Report - 2026-02-24T00:00:30Z

## Executive Summary:
- **High Attack Volume:** 2,275 attacks were observed in the past hour.
- **Geographic Concentration:** The United States was the top attacking country, accounting for 1,295 attacks.
- **Dominant Aggressor:** The IP address 185.242.226.46, associated with DigitalOcean, was the most active attacker with 142 attacks.
- **Common Vulnerabilities:** The most frequently observed alert signature was "GPL INFO VNC server response" (216 occurrences).
- **Exploitation Activity:** There were attempts to exploit several CVEs, with CVE-2024-14007 being the most frequent.
- **Credential Stuffing:** Common usernames and passwords like "admin", "user", "test1" and "123456", "12345678" were frequently used in attacks.

## Detailed Analysis:

**Total Attacks:**
- 2,275

**Top Attacking Countries:**
- United States: 1295
- Switzerland: 134
- Netherlands: 128
- Russia: 121
- Canada: 110

**Notable IP Reputations:**
- known attacker: 1301
- mass scanner: 74
- bot, crawler: 5

**Common Alert Categories:**
- Generic Protocol Command Decode: 428
- Misc activity: 355
- Misc Attack: 246
- Attempted Information Leak: 154
- Potentially Bad Traffic: 15
- Attempted Administrator Privilege Gain: 10
- Detection of a Network Scan: 7
- Web Application Attack: 3
- Detection of a Denial of Service Attack: 1
- access to a potentially vulnerable web application: 1

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 216
- 2228000 - SURICATA SSH invalid banner: 209
- 2001984 - ET INFO SSH session in progress on Unusual Port: 95
- 2023753 - ET SCAN MS Terminal Server Traffic on Non-standard Port: 94
- 2200003 - SURICATA IPv4 truncated packet: 55
- 2200122 - SURICATA AF-PACKET truncated packet: 55
- 2402000 - ET DROP Dshield Block Listed Source group 1: 50
- 2009582 - ET SCAN NMAP -sS window 1024: 48
- 2210051 - SURICATA STREAM Packet with broken ack: 38
- 2001978 - ET INFO SSH session in progress on Expected Port: 25

**ASN Information:**
- 14061 - DigitalOcean, LLC: 320
- 202425 - IP Volume inc: 281
- 47890 - Unmanaged Ltd: 199
- 51852 - Private Layer INC: 134
- 396982 - Google LLC: 118
- 209334 - Modat B.V.: 106
- 8075 - Microsoft Corporation: 99
- 63949 - Akamai Connected Cloud: 88
- 49505 - JSC Selectel: 83
- 63023 - GTHost: 73

**Source IP Addresses:**
- 185.242.226.46: 142
- 46.19.137.194: 134
- 129.212.184.194: 112
- 167.17.66.238: 73
- 4.255.221.217: 70
- 103.53.231.159: 65
- 85.217.149.26: 59
- 134.199.197.108: 56
- 45.87.249.140: 55
- 165.245.138.210: 53

**Country to Port Mapping:**
- Canada:
  - 8728: 4
  - 1182: 1
  - 1251: 1
  - 1284: 1
  - 1285: 1
  - 1592: 1
  - 1718: 1
  - 1756: 1
  - 1926: 1
  - 1927: 1
- Germany:
  - 1234: 15
  - 2904: 4
  - 27372: 4
  - 7473: 3
  - 7537: 3
  - 18001: 3
  - 5555: 2
  - 18080: 2
  - 8090: 1
  - 8545: 1
- Netherlands:
  - 9100: 16
  - 17000: 16
  - 17001: 8
  - 7443: 5
  - 22: 4
  - 6037: 4
  - 5432: 3
  - 3748: 2
  - 10369: 2
  - 32883: 2
- Romania:
  - 22: 4
  - 3030: 2
  - 4545: 2
  - 16532: 2
  - 25213: 2
  - 27003: 2
  - 34552: 2
  - 36742: 2
  - 42759: 2
  - 43442: 2
- Russia:
  - 4786: 11
  - 2375: 10
  - 7547: 8
  - 33000: 8
  - 11111: 6
  - 33333: 6
  - 33896: 6
  - 3401: 4
  - 33002: 4
  - 33008: 4
- Seychelles:
  - 22: 11
- Switzerland:
  - 5435: 133
  - 5432: 1
- United Kingdom:
  - 80: 3
  - 9000: 2
  - 10443: 2
  - 11443: 2
  - 22: 1
  - 443: 1
  - 1548: 1
  - 3732: 1
  - 4668: 1
  - 5864: 1
- United States:
  - 5902: 112
  - 5984: 96
  - 80: 91
  - 1455: 78
  - 5903: 57
  - 5901: 54
  - 8008: 43
  - 8728: 21
  - 9002: 11
  - 2078: 10
- Vietnam:
  - 22: 13

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 6
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2016-20016 CVE-2016-20016: 1
- CVE-2021-3449 CVE-2021-3449: 1
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- admin: 21
- user: 13
- test1: 8
- remote1: 5
- ftpuser: 4
- postgres: 4
- root: 3
- AdminGPON: 2
- agent: 1
- default: 1

**Passwords:**
- 123456: 5
- 12345678: 4
- 1234: 3
- : 2
- 123: 2
- 1664: 2
- 17011991: 2
- 17021991: 2
- 17031985: 2
- 17041984: 2

**OS Distribution:**
- Windows NT kernel: 20763
- Linux 2.2.x-3.x: 15425
- Linux 3.1-3.10: 2033
- Linux 3.11 and newer: 1356
- Linux 3.x: 705
- Linux 2.2.x-3.x (barebone): 451
- Linux 2.2.x-3.x (no timestamps): 393
- Windows NT kernel 5.x: 112
- Windows 7 or 8: 77
- Mac OS X: 11

**Hyper-aggressive IPs:**
- 185.242.226.46: 142
- 46.19.137.194: 134
- 129.212.184.194: 112
