# Honeypot Attack Report - 2026-02-21T00:00:25Z

## Executive Summary:
- A high volume of attacks (14,098) were observed in the past hour.
- The majority of attacks originated from Paraguay (9,774) and South Africa (2,059).
- The most aggressive IP addresses were 45.175.157.3 (Paraguay) and 102.33.155.122 (South Africa).
- Brute-force attempts were common, with "root" being the most frequently used username.
- A significant number of attacks targeted SSH (port 22) and Windows SMB (port 445).
- Several CVEs were targeted, with CVE-2024-14007 being the most frequent.

## Detailed Analysis:

**Total Attacks:**
- 14,098

**Top Attacking Countries:**
- Paraguay: 9,774
- South Africa: 2,059
- United States: 884
- Germany: 526
- Romania: 193

**Notable IP Reputations:**
- known attacker: 1,759
- mass scanner: 154

**Common Alert Categories:**
- Generic Protocol Command Decode: 1,048
- Misc activity: 434
- Misc Attack: 350
- Attempted Information Leak: 66
- Potentially Bad Traffic: 25

**Alert Signatures:**
- 2200003: SURICATA IPv4 truncated packet (348)
- 2200122: SURICATA AF-PACKET truncated packet (348)
- 2228000: SURICATA SSH invalid banner (229)
- 2100560: GPL INFO VNC server response (228)
- 2001984: ET INFO SSH session in progress on Unusual Port (127)

**ASN Information:**
- 267837 (Vicente Sosa Peralta): 9,774
- 327782 (METROFIBRE-NETWORX): 2,059
- 210006 (Shereverov Marat Ahmedovich): 450
- 47890 (Unmanaged Ltd): 356
- 396982 (Google LLC): 212

**Source IP Addresses:**
- 45.175.157.3: 9,774
- 102.33.155.122: 2,059
- 178.20.210.32: 450
- 86.54.24.29: 184
- 185.242.226.46: 85
- 2.57.122.208: 75
- 2.57.122.96: 75
- 172.86.126.140: 66
- 172.86.127.82: 66
- 185.242.226.45: 52

**Country to Port Mapping:**
- Germany:
  - 22: 90
  - 50000: 10
  - 7510: 4
  - 8083: 4
  - 11189: 4
- Paraguay:
  - 22: 1955
- Romania:
  - 22: 31
  - 2325: 2
  - 6176: 2
  - 7589: 2
  - 14067: 2
- South Africa:
  - 445: 2059
- United States:
  - 8983: 13
  - 8834: 10
  - 16000: 10
  - 5905: 9
  - 20001: 9

**CVEs Exploited:**
- CVE-2024-14007
- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012

**Usernames:**
- root: 1,979
- admin: 28
- sa: 11
- ubuntu: 6
- user: 6
- git: 5
- pi: 5
- sol: 4
- test: 4
- debian: 3

**Passwords:**
- 1234: 12
- pfsense: 7
- dietpi: 6
- test: 5
- : 4
- 123123: 4
- Arcanoid_01: 4
- password: 4
- 1234567890: 3
- 1q2w3e4r: 3

**OS Distribution:**
- Linux 2.2.x-3.x: 4,412
- Windows NT kernel: 4,371
- Linux 2.2.x-3.x (barebone): 398
- Windows NT kernel 5.x: 152
- Linux 2.2.x-3.x (no timestamps): 249

**Hyper-aggressive IPs:**
- 45.175.157.3: 9,774
- 102.33.155.122: 2,059
- 178.20.210.32: 450
- 86.54.24.29: 184
