# Honeypot Attack Report - 2026-02-20T17:00:23Z

## Executive Summary:
- **Total Attacks**: 6223 attacks were observed in the last hour.
- **Top Attacker**: Bolivia was the source of the highest number of attacks (1806), with the most aggressive IP being 200.105.151.2.
- **Dominant ASN**: AS26210 (AXS Bolivia S. A.) was the most active ASN, responsible for 1806 attacks.
- **High-Volume Signatures**: The most frequent alert signature was "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" with 1210 occurrences.
- **Common Target Ports**: Port 445 (SMB) was the most targeted port, primarily from Bolivia and the United States.
- **Operating Systems**: The most commonly observed operating system was Windows NT kernel.

## Detailed Analysis:

**Total Attacks**: 6223

**Top Attacking Countries**:
- Bolivia: 1806
- United States: 1685
- India: 1488
- United Kingdom: 340
- Latvia: 256

**Notable IP Reputations**:
- known attacker: 1150
- mass scanner: 197

**Common Alert Categories**:
- Generic Protocol Command Decode: 2427
- Attempted Administrator Privilege Gain: 1215
- Misc activity: 851
- Misc Attack: 326
- Attempted Information Leak: 66

**Alert Signatures**:
- 2024766 - ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1210
- 2200003 - SURICATA IPv4 truncated packet: 1123
- 2200122 - SURICATA AF-PACKET truncated packet: 1123
- 2100560 - GPL INFO VNC server response: 734
- 2001978 - ET INFO SSH session in progress on Expected Port: 68

**ASN Information**:
- 14061 - DigitalOcean, LLC: 2005
- 26210 - AXS Bolivia S. A.: 1806
- 701 - Verizon Business: 799
- 208885 - Noyobzoda Faridduni Saidilhom: 256
- 396982 - Google LLC: 185

**Source IP Addresses**:
- 200.105.151.2: 1806
- 68.183.87.253: 1439
- 173.73.62.72: 799
- 86.54.24.29: 256
- 188.166.156.16: 216

**Country to Port Mapping**:
- Bolivia
  - 445: 1806
- India
  - 22: 288
  - 445: 44
  - 23: 2
- Latvia
  - 22: 53
- United Kingdom
  - 22: 39
  - 9004: 8
  - 27963: 7
- United States
  - 445: 802
  - 11211: 43
  - 15672: 35

**CVEs Exploited**:
- CVE-2010-0569: 2
- CVE-2024-14007 CVE-2024-14007: 2
- CVE-2002-0013 CVE-2002-0012: 1
- CVE-2006-2369: 1
- CVE-2023-26801 CVE-2023-26801: 1

**Usernames**:
- root: 83
- admin: 33
- deploy: 12
- deployer: 7
- sshd: 7
- user: 7
- bot: 6
- jenkins: 6
- kafka: 6
- www-data: 6

**Passwords**:
- 123456: 60
- 1234: 16
- 123: 14
- admin: 13
- password: 13

**OS Distribution**:
- Linux 2.2.x-3.x: 15797
- Windows NT kernel: 18950
- Windows NT kernel 5.x: 10132
- Linux 2.2.x-3.x (barebone): 367
- Linux 2.2.x-3.x (no timestamps): 301

**Hyper-aggressive IPs**:
- 200.105.151.2: 1806
- 68.183.87.253: 1439
- 173.73.62.72: 799

**Other Notable Deviations**:
- High concentration of attacks from a single IP (200.105.151.2) in Bolivia targeting port 445.
