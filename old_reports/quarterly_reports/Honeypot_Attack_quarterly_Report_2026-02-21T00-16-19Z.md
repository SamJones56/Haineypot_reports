# Honeypot Attack Report - 2026-02-21T00:15:31Z

## Executive Summary:
- **High Attack Volume:** A total of 62,556 attacks were observed in the last 6 hours.
- **Dominant Attacker:** A single IP address, 45.175.157.3 from Paraguay, associated with ASN 267837 (Vicente Sosa Peralta), was responsible for the majority of the attacks (35,782).
- **Geographic Concentration:** Paraguay was the top attacking country, followed by the United States, Vietnam, South Africa, and Germany.
- **Common Tactics:** The most frequent alert category was "Generic Protocol Command Decode". The most common usernames and passwords observed were "root" and "123456" respectively.
- **Operating System Distribution:** The most common operating systems identified were Linux 2.2.x-3.x and Windows NT kernel.
- **Hyper-aggressive Behavior:** The IP address 45.175.157.3 exhibited hyper-aggressive behavior, launching a significantly higher number of attacks compared to other sources.

## Detailed Analysis:

**Total Attacks:**
- 62,556

**Top Attacking Countries:**
- Paraguay: 35,782
- United States: 6,083
- Vietnam: 3,167
- South Africa: 3,148
- Germany: 2,930

**Notable IP Reputations:**
- known attacker: 11,763
- mass scanner: 817
- tor exit node: 14
- bot, crawler: 7

**Common Alert Categories:**
- Generic Protocol Command Decode: 8,976
- Misc activity: 2,568
- Misc Attack: 1,932
- Attempted Information Leak: 397
- Potentially Bad Traffic: 257

**Alert Signatures:**
- 2200003 - SURICATA IPv4 truncated packet: 3,594
- 2200122 - SURICATA AF-PACKET truncated packet: 3,594
- 2100560 - GPL INFO VNC server response: 1,276
- 2228000 - SURICATA SSH invalid banner: 989
- 2001984 - ET INFO SSH session in progress on Unusual Port: 548

**ASN Information:**
- 267837 - Vicente Sosa Peralta: 35,782
- 14061 - DigitalOcean, LLC: 4,914
- 327782 - METROFIBRE-NETWORX: 3,148
- 7552 - Viettel Group: 3,104
- 210006 - Shereverov Marat Ahmedovich: 2,274

**Source IP Addresses:**
- 45.175.157.3: 35,782
- 102.33.155.122: 3,148
- 116.96.45.105: 3,104
- 178.20.210.32: 2,274
- 170.64.183.111: 1,756

**Country to Port Mapping:**
- **Germany:**
  - 22: 514
  - 80: 26
  - 9100: 24
  - 50000: 10
  - 8686: 8
- **Paraguay:**
  - 22: 7,156
  - 2222: 1
- **South Africa:**
  - 445: 3,148
- **United States:**
  - 80: 186
  - 22: 164
  - 23: 120
  - 8728: 55
  - 8008: 46
- **Vietnam:**
  - 445: 3,104
  - 19800: 8
  - 22: 7
  - 9009: 7
  - 9588: 7

**CVEs Exploited:**
- CVE-2006-2369: 52
- CVE-2024-14007 CVE-2024-14007: 20
- CVE-2021-3449 CVE-2021-3449: 9
- CVE-2019-11500 CVE-2019-11500: 8
- CVE-2025-55182 CVE-2025-55182: 4

**Usernames:**
- root: 7,592
- admin: 186
- sa: 116
- postgres: 90
- oracle: 74
- user: 63
- sol: 57
- ubuntu: 51
- solana: 37
- sshd: 36

**Passwords:**
- 123456: 92
- password: 89
- 1234: 71
- 123: 51
- pfsense: 49

**OS Distribution:**
- Linux 2.2.x-3.x: 57,685
- Windows NT kernel: 82,335
- Linux 2.2.x-3.x (barebone): 2,254
- Windows NT kernel 5.x: 623
- Linux 2.2.x-3.x (no timestamps): 1,881

**Hyper-aggressive IPs:**
- 45.175.157.3: 35,782 attacks
