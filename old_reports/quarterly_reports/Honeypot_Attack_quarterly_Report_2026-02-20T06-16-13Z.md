
# Honeypot Attack Report - 2026-02-20T06:15:13Z

Executive Summary:
- Over 33,000 attacks were observed in the last 6 hours.
- Vietnam was the dominant source of attacks, with over 12,000 attacks.
- The most active IP address was 103.237.145.16, associated with "Long Van Soft Solution JSC".
- The most common alert category was "Generic Protocol Command Decode".
- The most frequent alert signature was "GPL INFO VNC server response".
- Default credentials such as "root" and "admin" with common passwords are still being targeted.

Detailed Analysis:

Total Attacks:
- 33856

Top Attacking Countries:
- Vietnam: 12688
- United States: 7136
- India: 2863
- Singapore: 2586
- Germany: 1792

Notable IP Reputations:
- known attacker: 21014
- mass scanner: 1327
- compromised: 11
- bot, crawler: 4
- tor exit node: 4

Common Alert Categories:
- Generic Protocol Command Decode: 24761
- Misc activity: 14305
- Misc Attack: 2495
- Attempted Information Leak: 471
- Potentially Bad Traffic: 296
- Attempted Administrator Privilege Gain: 113
- Web Application Attack: 22
- Detection of a Network Scan: 18
- Not Suspicious Traffic: 13
- A Network Trojan was detected: 12

Alert Signatures:
- 2100560 - GPL INFO VNC server response: 13578
- 2200003 - SURICATA IPv4 truncated packet: 11855
- 2200122 - SURICATA AF-PACKET truncated packet: 11855
- 2402000 - ET DROP Dshield Block Listed Source group 1: 841
- 2001978 - ET INFO SSH session in progress on Expected Port: 325
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 251
- 2009582 - ET SCAN NMAP -sS window 1024: 246
- 2023753 - ET SCAN MS Terminal Server Traffic on Non-standard Port: 172
- 2210048 - SURICATA STREAM reassembly sequence GAP -- missing packet(s): 165
- 2210051 - SURICATA STREAM Packet with broken ack: 151

ASN Information:
- 131414 - Long Van Soft Solution JSC: 12686
- 14061 - DigitalOcean, LLC: 6481
- 8075 - Microsoft Corporation: 2426
- 396982 - Google LLC: 1455
- 45117 - Ishans Network: 1344
- 174 - Cogent Communications, LLC: 1094
- 48090 - Techoff Srv Limited: 1090
- 213412 - ONYPHE SAS: 669
- 51852 - Private Layer INC: 665
- 47890 - Unmanaged Ltd: 620

Source IP Addresses:
- 103.237.145.16: 12686
- 4.145.113.4: 2277
- 64.227.172.219: 1429
- 103.7.81.84: 1344
- 159.203.105.250: 1287
- 138.68.109.50: 1080
- 195.178.110.199: 899
- 46.19.137.194: 665
- 207.154.211.38: 276
- 2.57.122.210: 260

Country to Port Mapping:
- Germany
  - 22: 292
  - 80: 47
  - 8022: 8
  - 20793: 8
  - 31999: 8
- India
  - 445: 1344
  - 22: 293
  - 19700: 8
  - 31999: 8
  - 23: 2
- Singapore
  - 5903: 228
  - 5904: 228
  - 5905: 228
  - 5906: 228
  - 5907: 228
- United States
  - 22: 298
  - 80: 81
  - 5984: 66
  - 8728: 56
  - 445: 53
- Vietnam
  - 22: 2538

CVEs Exploited:
- CVE-2024-14007 CVE-2024-14007: 21
- CVE-2025-55182 CVE-2025-55182: 7
- CVE-2019-11500 CVE-2019-11500: 6
- CVE-2021-3449 CVE-2021-3449: 6
- CVE-2006-2369: 4
- CVE-2024-4577 CVE-2002-0953: 4
- CVE-2024-4577 CVE-2024-4577: 4
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 3
- CVE-2021-42013 CVE-2021-42013: 2
- CVE-2002-0606: 1

Usernames:
- root: 2813
- admin: 117
- sa: 102
- guest: 67
- user: 65
- postgres: 60
- test: 59
- dspace: 40
- oracle: 40
- ubuntu: 37

Passwords:
- 123456: 75
- password: 70
- 12345: 58
- 123456789: 57
- 12345678: 47
- welcome: 47
- : 44
- admin123: 40
- admin: 36
- letmein: 35

OS Distribution:
- Linux 2.2.x-3.x: 50750
- Linux 2.2.x-3.x (barebone): 2975
- Windows NT kernel: 71728
- Windows NT kernel 5.x: 56074
- Linux 3.11 and newer: 286
- Linux 2.2.x-3.x (no timestamps): 329
- Mac OS X: 124
- Linux 3.1-3.10: 79
- Windows 7 or 8: 165
- Windows XP: 10

Hyper-aggressive IPs:
- 103.237.145.16: 12686
- 4.145.113.4: 2277
- 64.227.172.219: 1429
- 103.7.81.84: 1344
- 159.203.105.250: 1287
- 138.68.109.50: 1080
