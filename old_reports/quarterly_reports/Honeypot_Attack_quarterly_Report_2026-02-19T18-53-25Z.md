# Honeypot Attack Report - 2026-02-19T18:52:38Z

## Executive Summary:
- Over the past 6 hours, the honeypot network observed 3,425 attacks, with the majority originating from the United States and Germany.
- A significant portion of the attacks (1,826) were attributed to ASN 14061 (DigitalOcean, LLC), indicating a concentration of malicious activity from this provider.
- The most frequent alert signatures were "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet", each with 7,415 occurrences, suggesting a prevalence of network scanning and reconnaissance activities.
- Brute-force attempts were common, with "root" and "admin" being the most targeted usernames, and "password" and "123456" as the most used passwords.
- Several CVEs were targeted, with CVE-2024-14007 being the most frequent.
- Four IP addresses were identified as hyper-aggressive, each launching over 250 attacks during the reporting period.

## Detailed Analysis:

### Total Attacks:
3425

### Top Attacking Countries:
- United States: 1002
- Germany: 921
- Australia: 352
- Singapore: 278
- United Kingdom: 216

### Notable IP Reputations:
- known attacker: 1278
- mass scanner: 145

### Common Alert Categories:
- Generic Protocol Command Decode: 14968
- Misc activity: 1817
- Misc Attack: 311
- Attempted Information Leak: 107
- Potentially Bad Traffic: 13

### Alert Signatures:
- 2200003, SURICATA IPv4 truncated packet: 7415
- 2200122, SURICATA AF-PACKET truncated packet: 7415
- 2100560, GPL INFO VNC server response: 1678
- 2402000, ET DROP Dshield Block Listed Source group 1: 88
- 2038967, ET INFO SSH-2.0-Go version string Observed in Network Traffic: 55

### ASN Information:
- 14061, DigitalOcean, LLC: 1826
- 135377, UCLOUD INFORMATION TECHNOLOGY HK LIMITED: 507
- 8075, Microsoft Corporation: 289
- 396982, Google LLC: 230
- 174, Cogent Communications, LLC: 163

### Source IP Addresses:
- 207.154.239.37: 298
- 104.248.249.212: 290
- 4.145.113.4: 278
- 165.227.161.214: 259
- 134.199.173.128: 180

### Country to Port Mapping:
- Australia:
  - 22: 67
- Germany:
  - 22: 170
  - 50001: 16
  - 9443: 14
- Singapore:
  - 5901: 28
  - 5902: 28
  - 5904: 28
- United Kingdom:
  - 22: 22
  - 8088: 16
  - 30443: 14
- United States:
  - 22: 54
  - 8081: 25
  - 2000: 18

### CVEs Exploited:
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2002-0013 CVE-2002-0012: 1
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2025-55182 CVE-2025-55182: 1

### Usernames:
- root: 108
- admin: 63
- debian: 28
- daemon: 24
- backup: 21
- user: 21
- test: 13
- administrator: 10
- ansible: 10
- postgres: 6

### Passwords:
- password: 21
- 123456: 20
- qwerty: 17
- 12345: 15
- 12345678: 12

### OS Distribution:
- Linux 2.2.x-3.x: 13340
- Windows NT kernel 5.x: 6534
- Linux 2.2.x-3.x (barebone): 484
- Linux 2.2.x-3.x (no timestamps): 78
- Linux 3.11 and newer: 27

### Hyper-aggressive IPs:
- 207.154.239.37: 298
- 104.248.249.212: 290
- 4.145.113.4: 278
- 165.227.161.214: 259
