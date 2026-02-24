# Honeypot Attack Report - 2026-02-23T22:00:30Z

## Executive Summary:
- **High-Volume Attack Activity:** A total of 4,903 attacks were observed in the past hour, with a significant concentration from a single source IP.
- **Dominant Attacker:** A single IP address, 173.249.27.120, associated with Contabo GmbH in France, was responsible for an overwhelming majority of the attacks, totaling 2,329 individual events.
- **Geographic Concentration:** Attacks were predominantly sourced from France (2,333) and the United States (1,134), indicating targeted campaigns from these regions.
- **Common Vulnerabilities:** The most frequently targeted vulnerabilities included CVE-2024-14007 and CVE-2025-55182, suggesting a focus on recently disclosed security flaws.
- **Credential Stuffing:** Brute-force attempts were prevalent, with common username/password combinations such as `root`/`123456` and `admin`/`123` being repeatedly used.
- **Operating System Landscape:** The attacking systems were primarily identified as Windows NT kernel and Linux 2.2.x-3.x, indicating a diverse range of attacker infrastructure.

## Detailed Analysis:

**Total Attacks:**
- 4,903

**Top Attacking Countries:**
- France: 2,333
- United States: 1,134
- Seychelles: 270
- Romania: 227
- Singapore: 194

**Notable IP Reputations:**
- known attacker: 1,802
- mass scanner: 60
- bot, crawler: 10

**Common Alert Categories:**
- Generic Protocol Command Decode: 5,607
- Misc activity: 447
- Misc Attack: 275
- Attempted Information Leak: 100
- Attempted Administrator Privilege Gain: 21
- Potentially Bad Traffic: 11
- Web Application Attack: 3
- access to a potentially vulnerable web application: 2
- Detection of a Denial of Service Attack: 1
- Malware Command and Control Activity Detected: 1

**Alert Signatures:**
- 2200003 - SURICATA IPv4 truncated packet: 2,532
- 2200122 - SURICATA AF-PACKET truncated packet: 2,532
- 2228000 - SURICATA SSH invalid banner: 239
- 2100560 - GPL INFO VNC server response: 218
- 2210048 - SURICATA STREAM reassembly sequence GAP -- missing packet(s): 111
- 2001984 - ET INFO SSH session in progress on Unusual Port: 107
- 2210010 - SURICATA STREAM 3way handshake wrong seq wrong ack: 62
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 61
- 2402000 - ET DROP Dshield Block Listed Source group 1: 53
- 2001978 - ET INFO SSH session in progress on Expected Port: 52

**ASN Information:**
- 51167 - Contabo GmbH: 2,332
- 14061 - DigitalOcean, LLC: 457
- 47890 - Unmanaged Ltd: 387
- 210006 - Shereverov Marat Ahmedovich: 270
- 8075 - Microsoft Corporation: 194
- 202425 - IP Volume inc: 179
- 131427 - AOHOAVIET: 155
- 51852 - Private Layer INC: 126
- 396982 - Google LLC: 115
- 16509 - Amazon.com, Inc.: 56

**Source IP Addresses:**
- 173.249.27.120: 2,329
- 45.87.249.140: 270
- 104.215.189.248: 180
- 103.53.231.159: 155
- 46.19.137.194: 126
- 129.212.184.194: 115
- 193.32.162.145: 90
- 2.57.122.96: 85
- 185.242.226.46: 65
- 134.199.197.108: 58

**Country to Port Mapping:**
- **China:**
  - 6379: 28
  - 10000: 9
  - 1967: 6
  - 9030: 5
  - 2323: 4
- **France:**
  - 443: 1,545
  - 80: 784
  - 3128: 3
  - 2200: 1
- **Netherlands:**
  - 9100: 32
  - 17001: 12
  - 6037: 8
  - 8728: 7
  - 80: 4
- **Romania:**
  - 22: 38
  - 5467: 2
  - 11343: 2
  - 15092: 2
  - 21060: 2
- **Seychelles:**
  - 22: 54
- **Singapore:**
  - 80: 181
  - 8415: 3
  - 8889: 3
  - 30013: 3
  - 6868: 2
- **Switzerland:**
  - 5434: 125
  - 5432: 1
- **United Kingdom:**
  - 1611: 7
  - 4444: 3
  - 5432: 3
  - 3352: 2
  - 13395: 2
- **United States:**
  - 5902: 115
  - 1444: 78
  - 5903: 66
  - 5901: 55
  - 11211: 37
- **Vietnam:**
  - 22: 31
  - 58603: 7

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 5
- CVE-2025-55182 CVE-2025-55182: 2
- CVE-2002-0013 CVE-2002-0012: 1
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2021-3449 CVE-2021-3449: 1

**Usernames:**
- root: 21
- admin: 20
- ubuntu: 10
- guest1: 8
- sol: 8
- test3: 8
- test4: 8
- solana: 6
- postgres: 5
- test2: 5

**Passwords:**
- 123456: 12
- 123: 9
- 12345678: 9
- 1234: 8
- admin: 4
- admin123: 4
- root123: 4
- solana: 3
- 1: 2
- 123solana: 2

**OS Distribution:**
- Windows NT kernel: 20,597
- Linux 2.2.x-3.x: 11,925
- Linux 2.2.x-3.x (no timestamps): 312
- Linux 2.2.x-3.x (barebone): 305
- Windows NT kernel 5.x: 181
- Mac OS X: 63
- Windows 7 or 8: 56
- Linux 3.11 and newer: 32
- Linux 3.1-3.10: 5
- Linux 2.4.x: 1

**Hyper-aggressive IPs:**
- 173.249.27.120: 2,329 attacks

**Unusual Credential Patterns:**
- No statistically significant unusual credential patterns were observed.

**Attacker Signatures / Taunts:**
- No specific attacker signatures or taunts were explicitly observed in the collected data.

**Malware/Botnet Filenames:**
- No malware or botnet filenames were explicitly observed in the collected data.

**Other Notable Deviations:**
- The high concentration of attacks from a single source IP (173.249.27.120) suggests a targeted and aggressive campaign rather than a distributed attack.
- The dominance of traffic to ports 443 and 80 from France indicates a focus on web-based exploits.
- The high number of "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet" alerts suggests that the honeypot is effectively detecting and logging malformed packets, which are often used in reconnaissance and evasion techniques.
