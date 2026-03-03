# Honeypot Attack Report - 2026-02-21T05:00:16Z

Executive Summary:
- The honeypot network observed 2,618 attacks in the past hour.
- The United States was the top attacking country, responsible for 914 attacks.
- The most active IP address was 178.20.210.32, with 400 observed attacks.
- "Generic Protocol Command Decode" was the most common alert category, with 1049 instances.
- The most frequently observed alert signature was "SURICATA IPv4 truncated packet," with 314 instances.
- The most common username and password combination was root and 123456.

Detailed Analysis:

Total Attacks:
- 2618

Top Attacking Countries:
- United States: 914
- Germany: 457
- China: 415
- United Kingdom: 341
- Romania: 153

Notable IP Reputations:
- known attacker: 1416
- mass scanner: 158

Common Alert Categories:
- Generic Protocol Command Decode: 1049
- Misc activity: 383
- Misc Attack: 351
- Attempted Information Leak: 48
- Attempted Administrator Privilege Gain: 24
- Potentially Bad Traffic: 15
- Web Application Attack: 10
- A Network Trojan was detected: 6
- Detection of a Denial of Service Attack: 3
- Attempted User Privilege Gain: 2

Alert Signatures:
- 2200003: SURICATA IPv4 truncated packet (314)
- 2200122: SURICATA AF-PACKET truncated packet (314)
- 2100560: GPL INFO VNC server response (204)
- 2228000: SURICATA SSH invalid banner (200)
- 2402000: ET DROP Dshield Block Listed Source group 1 (93)
- 2001984: ET INFO SSH session in progress on Unusual Port (91)
- 2210041: SURICATA STREAM RST recv but no session (88)
- 2001978: ET INFO SSH session in progress on Expected Port (42)
- 2009582: ET SCAN NMAP -sS window 1024 (38)
- 2210048: SURICATA STREAM reassembly sequence GAP -- missing packet(s) (36)

ASN Information:
- 210006: Shereverov Marat Ahmedovich (400)
- 4134: Chinanet (394)
- 14061: DigitalOcean, LLC (375)
- 47890: Unmanaged Ltd (274)
- 396982: Google LLC (201)
- 14956: RouterHosting LLC (123)
- 51852: Private Layer INC (97)
- 16509: Amazon.com, Inc. (91)
- 6939: Hurricane Electric LLC (61)
- 398324: Censys, Inc. (47)

Source IP Addresses:
- 178.20.210.32: 400
- 124.225.88.153: 390
- 134.209.180.181: 278
- 2.57.122.208: 110
- 46.19.137.194: 97
- 172.86.126.140: 57
- 172.86.127.82: 57
- 64.188.98.66: 46
- 185.242.226.45: 32
- 16.58.56.214: 26

Country to Port Mapping:
- China
  - 23: 192
  - 49155: 6
  - 7014: 5
  - 8085: 5
  - 28080: 4
  - 2222: 2
  - 8010: 1
- France
  - 80: 4
  - 3128: 3
  - 3300: 2
  - 3397: 2
  - 3405: 2
  - 4443: 2
  - 5585: 2
  - 7274: 2
  - 22273: 2
  - 33331: 2
- Germany
  - 22: 80
  - 5521: 8
  - 28954: 8
  - 3501: 4
  - 9080: 4
  - 28866: 4
  - 54928: 4
  - 6010: 3
  - 5555: 2
  - 7143: 2
- Hong Kong
  - 7777: 14
  - 2550: 5
  - 4567: 5
  - 2377: 1
  - 3750: 1
  - 4003: 1
  - 10381: 1
  - 11098: 1
  - 61016: 1
- Netherlands
  - 6036: 8
  - 6037: 8
  - 8728: 7
  - 22: 6
  - 80: 4
  - 17000: 4
  - 8545: 3
  - 81: 2
  - 3000: 2
  - 3306: 2
- Romania
  - 22: 24
  - 3960: 2
  - 12281: 2
  - 13302: 2
  - 14796: 2
  - 17762: 2
  - 23298: 2
  - 30347: 2
  - 35472: 2
  - 38517: 2
- Russia
  - 11211: 20
  - 443: 1
  - 1604: 1
  - 50000: 1
- Switzerland
  - 15432: 96
  - 5432: 1
- United Kingdom
  - 22: 53
  - 3306: 3
  - 5432: 3
  - 4170: 2
  - 9014: 2
  - 10073: 2
  - 13416: 2
  - 45131: 2
  - 45936: 2
  - 47102: 2
- United States
  - 80: 52
  - 29092: 35
  - 15672: 34
  - 5500: 32
  - 8728: 14
  - 9200: 13
  - 8100: 11
  - 30003: 11
  - 443: 10
  - 9043: 10

CVEs Exploited:
- CVE-2024-14007
- CVE-2021-3449
- CVE-2019-11500
- CVE-2024-4577
- CVE-2002-0953
- CVE-2021-41773
- CVE-2021-42013
- CVE-2023-26801
- CVE-2025-55182

Usernames:
- root: 68
- user: 7
- admin: 5
- postgres: 4
- ubuntu: 4
- administrator: 3
- backup: 3
- bin: 3
- deer: 3
- dummy: 3

Passwords:
- 123456: 12
- : 5
- P@ssw0rd: 4
- aan15: 3
- admin01: 3
- deer: 3
- dummy: 3
- password: 3
- remote: 3
- smoker666: 3

OS Distribution:
- Linux 2.2.x-3.x: 6854
- Windows NT kernel: 3317
- Linux 2.2.x-3.x (barebone): 371
- Windows NT kernel 5.x: 126
- Linux 2.2.x-3.x (no timestamps): 166
- Linux 3.11 and newer: 35
- Mac OS X: 12
- Linux 2.4.x: 1
- Linux 3.1-3.10: 1
- Nintendo 3DS: 2

Hyper-aggressive IPs:
- 178.20.210.32: 400
- 124.225.88.153: 390
- 134.209.180.181: 278
- 2.57.122.208: 110
