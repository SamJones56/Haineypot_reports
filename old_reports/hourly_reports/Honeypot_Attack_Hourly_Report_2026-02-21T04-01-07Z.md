
# Honeypot Attack Report - 2026-02-21T04:00:27Z

## Executive Summary:
- Over 2,300 attacks were observed in the past hour, with the United States, Germany, and China being the primary sources of origin.
- The most prominent attacker, IP 178.20.210.32, is associated with ASN 210006 (Shereverov Marat Ahmedovich).
- A significant portion of the attacks were classified as "known attacker" (1374) and "mass scanner" (133), indicating automated and targeted attacks.
- The most frequent alert signature was "SURICATA SSH invalid banner", suggesting a high volume of SSH scanning activity.
- The most common credential pairs used in brute-force attempts were "root/123456" and "admin/admin".
- The dominant operating system identified among attackers was Linux 2.2.x-3.x.

## Detailed Analysis:

**Total Attacks:**
- 2369

**Top Attacking Countries:**
- United States: 904
- Germany: 482
- China: 439
- Romania: 135
- United Kingdom: 98

**Notable IP Reputations:**
- known attacker: 1374
- mass scanner: 133

**Common Alert Categories:**
- Generic Protocol Command Decode: 686
- Misc activity: 416
- Misc Attack: 346
- Attempted Information Leak: 58
- Potentially Bad Traffic: 9

**Alert Signatures:**
- 2228000 - SURICATA SSH invalid banner: 242
- 2100560 - GPL INFO VNC server response: 238
- 2200003 - SURICATA IPv4 truncated packet: 175
- 2200122 - SURICATA AF-PACKET truncated packet: 175
- 2001984 - ET INFO SSH session in progress on Unusual Port: 111

**ASN Information:**
- 210006, Shereverov Marat Ahmedovich: 436
- 4134, Chinanet: 419
- 47890, Unmanaged Ltd: 289
- 14061, DigitalOcean, LLC: 192
- 396982, Google LLC: 177

**Source IP Addresses:**
- 178.20.210.32: 436
- 124.225.88.153: 406
- 2.57.122.208: 95
- 185.242.226.45: 69
- 172.86.126.140: 60

**Country to Port Mapping:**
- China
  - 23: 206
  - 50100: 14
  - 7014: 5
  - 9109: 5
  - 2095: 2
- Germany
  - 22: 87
  - 8083: 4
  - 28866: 4
  - 33282: 4
  - 62472: 4
- Romania
  - 22: 19
  - 6229: 2
  - 6646: 2
  - 6840: 2
  - 9170: 2
- United Kingdom
  - 1419: 8
  - 1420: 8
  - 443: 2
  - 1212: 2
  - 1311: 2
- United States
  - 9093: 57
  - 8009: 35
  - 2375: 34
  - 22: 14
  - 8099: 12

**CVEs Exploited:**
- CVE-2006-2369: 5
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- root: 37
- ftp: 13
- admin: 10
- ubuntu: 5
- ftpuser: 3
- sol: 3
- Admin: 2
- daemon: 2
- git: 2
- install: 2

**Passwords:**
- 123456: 6
- admin: 5
- 123: 3
- 123456789: 3
- qwerty: 3

**OS Distribution:**
- Linux 2.2.x-3.x: 5843
- Windows NT kernel: 3692
- Linux 2.2.x-3.x (barebone): 320
- Windows NT kernel 5.x: 155
- Linux 3.11 and newer: 23

**Hyper-aggressive IPs:**
- 178.20.210.32: 436
- 124.225.88.153: 406

**Unusual Credential Patterns:**
- None observed.

**Attacker Signatures / Taunts:**
- None observed.

**Malware/Botnet Filenames:**
- None observed.

**Other Notable Deviations:**
- None observed.
