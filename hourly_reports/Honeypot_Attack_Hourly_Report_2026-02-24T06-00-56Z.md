
# Honeypot Attack Report - 2026-02-24T06:00:15Z

Executive Summary:
- High volume of attacks (8598) were observed in the last hour.
- France, India, and the United States were the top three attacking countries.
- The most prominent attacker IP was 203.194.103.78 from India, associated with ASN ONEOTT INTERTAINMENT LIMITED.
- A significant portion of the attacks were categorized as "Generic Protocol Command Decode".
- The most frequent alert signatures were "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet".
- Common credentials "test"/"123456" and "admin"/"password" were observed.

Detailed Analysis:

Total Attacks:
- 8598

Top Attacking Countries:
- France: 2271
- India: 1963
- United States: 1199
- United Kingdom: 492
- Canada: 271

Notable IP Reputations:
- known attacker: 3788
- bot, crawler: 1622
- mass scanner: 140

Common Alert Categories:
- Generic Protocol Command Decode: 3388
- Misc activity: 443
- Misc Attack: 350
- Attempted Information Leak: 66
- Potentially Bad Traffic: 8
- Attempted Administrator Privilege Gain: 6
- Detection of a Network Scan: 4
- Detection of a Denial of Service Attack: 2
- Not Suspicious Traffic: 1

Alert Signatures:
- 2200003 - SURICATA IPv4 truncated packet: 1225
- 2200122 - SURICATA AF-PACKET truncated packet: 1225
- 2221010 - SURICATA HTTP unable to match response to request: 372
- 2100560 - GPL INFO VNC server response: 216
- 2228000 - SURICATA SSH invalid banner: 215
- 2402000 - ET DROP Dshield Block Listed Source group 1: 122
- 2001984 - ET INFO SSH session in progress on Unusual Port: 108
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 61
- 2001978 - ET INFO SSH session in progress on Expected Port: 48
- 2210048 - SURICATA STREAM reassembly sequence GAP -- missing packet(s): 48

ASN Information:
- 211590 - Bucklog SARL: 2268
- 17665 - ONEOTT INTERTAINMENT LIMITED: 1955
- 14061 - DigitalOcean, LLC: 907
- 209334 - Modat B.V.: 261
- 131427 - AOHOAVIET: 230
- 47890 - Unmanaged Ltd: 211
- 396982 - Google LLC: 141
- 16509 - Amazon.com, Inc.: 132
- 51852 - Private Layer INC: 72
- 6939 - Hurricane Electric LLC: 61

Source IP Addresses:
- 203.194.103.78: 1955
- 185.177.72.23: 1793
- 127.0.0.1: 1620
- 157.245.36.181: 475
- 103.53.231.159: 230
- 185.177.72.38: 163
- 185.177.72.13: 156
- 185.177.72.49: 156
- 129.212.184.194: 112
- 46.19.137.194: 72

Country to Port Mapping:
- Canada
  - 8728: 4
  - 1024: 3
  - 1025: 3
  - 3083: 3
  - 5005: 3
  - 28080: 3
  - 1337: 2
  - 1457: 2
  - 1717: 2
  - 1901: 2
- France
  - 80: 2268
  - 3128: 3
- Germany
  - 8086: 14
  - 22: 5
  - 7012: 4
  - 9807: 4
  - 12447: 4
  - 12161: 3
  - 2376: 2
  - 7000: 2
- India
  - 445: 1955
  - 22: 2
  - 23: 1
- Netherlands
  - 1337: 40
  - 6036: 16
  - 6037: 8
  - 9100: 8
  - 17001: 8
  - 22: 4
  - 4145: 3
  - 8545: 3
  - 80: 2
  - 12059: 2
- Romania
  - 22: 10
  - 587: 8
  - 443: 6
  - 2382: 2
  - 7221: 2
  - 7697: 2
  - 8561: 2
  - 10851: 2
  - 14119: 2
  - 25073: 2
- Switzerland
  - 25432: 71
  - 5432: 1
- United Kingdom
  - 22: 95
  - 5432: 3
  - 27017: 2
  - 80: 1
  - 2878: 1
  - 8516: 1
  - 18396: 1
  - 21724: 1
  - 26040: 1
  - 28484: 1
- United States
  - 1577: 117
  - 5902: 112
  - 9093: 60
  - 5903: 57
  - 5901: 56
  - 1557: 39
  - 8009: 35
  - 81: 19
  - 2222: 16
  - 7548: 12
- Vietnam
  - 22: 46

CVEs Exploited:
- CVE-2024-14007 CVE-2024-14007: 5
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2019-11500 CVE-2019-11500: 1

Usernames:
- test: 44
- admin: 17
- ftp: 5
- ssh: 5
- support: 5
- arch: 4
- backup: 4
- centos: 4
- client: 4
- daemon: 4

Passwords:
- 123456: 28
- password: 26
- 12345678: 23
- 111111: 2
- 123123: 2
- 12345: 2
- 1234567: 2
- 123456789: 2
- 1234567890: 2
- 13091985: 2

OS Distribution:
- Linux 2.2.x-3.x: 13666
- Windows NT kernel: 11453
- Windows 7 or 8: 1960
- Linux 2.2.x-3.x (barebone): 307
- Linux 2.2.x-3.x (no timestamps): 275
- Windows NT kernel 5.x: 165
- Linux 3.11 and newer: 30
- Mac OS X: 29
- Linux 3.1-3.10: 3
- Windows XP: 1

Hyper-aggressive IPs:
- 203.194.103.78: 1955
- 185.177.72.23: 1793
- 127.0.0.1: 1620
- 157.245.36.181: 475
- 103.53.231.159: 230
- 185.177.72.38: 163
- 185.177.72.13: 156
- 185.177.72.49: 156
- 129.212.184.194: 112
- 46.19.137.194: 72
