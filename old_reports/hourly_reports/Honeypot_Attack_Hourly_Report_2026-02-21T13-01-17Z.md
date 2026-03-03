# Honeypot Attack Report - 2026-02-21T13:00:14Z

Executive Summary:
- Over the past hour, a total of 3,675 attacks were observed.
- The most prominent attacking country was Singapore, accounting for 1,524 of the total attacks.
- The dominant actor was IP address 128.199.198.62 with 1,505 attacks, originating from the ASN DigitalOcean, LLC in Singapore.
- The most common alert category was "Generic Protocol Command Decode" with 6,900 instances.
- Exploitation of CVE-2021-3449 was observed, and the most common username attempted was "root".
- The most frequent alert signatures were "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet", both with 3,254 occurrences.

Detailed Analysis:

Total Attacks:
- 3675

Top Attacking Countries:
- Singapore: 1524
- United States: 502
- Bangladesh: 362
- Romania: 219
- Canada: 200

Notable IP Reputations:
- known attacker: 2673
- mass scanner: 134

Common Alert Categories:
- Generic Protocol Command Decode: 6900
- Misc activity: 443
- Misc Attack: 350
- Attempted Information Leak: 189
- Attempted Administrator Privilege Gain: 49
- Web Application Attack: 7
- Detection of a Network Scan: 4
- Potentially Bad Traffic: 4
- Detection of a Denial of Service Attack: 3
- Successful Administrator Privilege Gain: 3

Alert Signatures:
- 2200003 - SURICATA IPv4 truncated packet: 3254
- 2200122 - SURICATA AF-PACKET truncated packet: 3254
- 2100560 - GPL INFO VNC server response: 226
- 2228000 - SURICATA SSH invalid banner: 204
- 2023753 - ET SCAN MS Terminal Server Traffic on Non-standard Port: 102
- 2402000 - ET DROP Dshield Block Listed Source group 1: 96
- 2001984 - ET INFO SSH session in progress on Unusual Port: 92
- 2210051 - SURICATA STREAM Packet with broken ack: 61
- 2001978 - ET INFO SSH session in progress on Expected Port: 58
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 53

ASN Information:
- 14061 - DigitalOcean, LLC: 1522
- 63526 - Systems Solutions & development Technologies Limited: 362
- 47890 - Unmanaged Ltd: 360
- 396982 - Google LLC: 240
- 209334 - Modat B.V.: 195
- 131427 - AOHOAVIET: 185
- 201002 - PebbleHost Ltd: 76
- 398324 - Censys, Inc.: 47
- 210006 - Shereverov Marat Ahmedovich: 46
- 6939 - Hurricane Electric LLC: 39

Source IP Addresses:
- 128.199.198.62: 1505
- 103.231.239.109: 362
- 103.53.231.159: 185
- 34.158.168.101: 99
- 2.57.122.238: 90
- 2.57.122.96: 90
- 85.217.149.15: 57
- 85.217.149.19: 53
- 45.87.249.145: 46
- 77.90.185.18: 37

Country to Port Mapping:
- Bangladesh:
  - 445: 362
- Canada:
  - 8728: 4
  - 50100: 3
  - 1060: 2
  - 2694: 2
  - 3181: 2
  - 5358: 2
  - 7016: 2
  - 9169: 2
  - 10565: 2
  - 12034: 2
- Germany:
  - 9664: 7
  - 8000: 6
  - 45990: 4
  - 3378: 2
  - 3395: 2
  - 4242: 2
  - 5151: 2
  - 10306: 2
  - 16971: 2
  - 20000: 2
- Netherlands:
  - 443: 97
  - 80: 13
  - 22: 4
  - 8090: 4
  - 25: 2
  - 81: 2
  - 2222: 2
  - 8022: 2
  - 50050: 2
  - 5555: 1
- Romania:
  - 22: 37
  - 3553: 2
  - 3818: 2
  - 4251: 2
  - 10590: 2
  - 11584: 2
  - 15514: 2
  - 18121: 2
  - 23259: 2
  - 24626: 2
- Seychelles:
  - 6036: 4
  - 44445: 2
  - 46148: 2
  - 46156: 2
  - 46157: 2
  - 46159: 2
  - 46164: 2
  - 46166: 2
  - 46169: 2
  - 46170: 2
- Singapore:
  - 22: 303
  - 2095: 3
  - 47920: 1
- United Kingdom:
  - 3388: 4
  - 80: 2
  - 1143: 2
  - 2052: 2
  - 3066: 2
  - 3773: 2
  - 3993: 2
  - 4531: 2
  - 4730: 2
  - 4949: 2
- United States:
  - 8888: 10
  - 6379: 9
  - 25: 8
  - 5570: 7
  - 22: 6
  - 9999: 5
  - 4321: 4
  - 4430: 4
  - 4444: 4
  - 7000: 4
- Vietnam:
  - 22: 37

CVEs Exploited:
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2002-0013 CVE-2002-0012: 1
- CVE-2023-26801 CVE-2023-26801: 1
- CVE-2024-14007 CVE-2024-14007: 1
- CVE-2025-55182 CVE-2025-55182: 1

Usernames:
- root: 349
- sol: 14
- ubuntu: 7
- user: 5
- admin: 4
- solana: 4
- solv: 4
- ethereum: 1
- jito: 1
- node: 1

Passwords:
- admin: 4
- root: 3
- 0000: 2
- 1: 2
- 1111: 2
- 112233: 2
- 12345678: 2
- 123456a: 2
- 159753: 2
- 4rfv$RFV: 2

OS Distribution:
- Linux 2.2.x-3.x: 12556
- Windows NT kernel: 11145
- Windows 7 or 8: 369
- Linux 2.2.x-3.x (barebone): 267
- Windows NT kernel 5.x: 174
- Linux 2.2.x-3.x (no timestamps): 93
- Linux 3.11 and newer: 28
- Linux 3.1-3.10: 18
- Mac OS X: 8
- FreeBSD: 1

Hyper-aggressive IPs:
- 128.199.198.62: 1505
- 103.231.239.109: 362
- 103.53.231.159: 185
- 34.158.168.101: 99
- 2.57.122.238: 90
- 2.57.122.96: 90
