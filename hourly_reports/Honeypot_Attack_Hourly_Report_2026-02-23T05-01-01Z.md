# Honeypot Attack Report - 2026-02-23T05:00:19Z

### Executive Summary:
- Over 4,400 attacks were recorded in the last hour, with the majority originating from the United States and India.
- A significant portion of attacking IPs (1,362) were identified with a "known attacker" reputation.
- The most frequent activity involved miscellaneous activities and generic protocol command decodes, with VNC and SSH-related signatures being the most common.
- Brute-force attempts were prevalent, with "root" being the most targeted username and "123456" the most common password.
- A single IP address, 59.145.41.149, was responsible for over 500 attacks, demonstrating hyper-aggressive behavior.
- The dominant attacking operating system appears to be Linux, based on p0f fingerprinting.

### Detailed Analysis:

**Total Attacks:**
- 4441

**Top Attacking Countries:**
- United States: 1614
- India: 1225
- France: 393
- Australia: 345
- Romania: 244

**Notable IP Reputations:**
- known attacker: 1362
- mass scanner: 197
- bot, crawler: 1

**Common Alert Categories:**
- Misc activity: 470
- Generic Protocol Command Decode: 449
- Misc Attack: 379
- Attempted Information Leak: 98
- Potentially Bad Traffic: 17

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 196
- 2228000 - SURICATA SSH invalid banner: 164
- 2402000 - ET DROP Dshield Block Listed Source group 1: 123
- 2001978 - ET INFO SSH session in progress on Expected Port: 103
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 97

**ASN Information:**
- 14061 - DigitalOcean, LLC: 2061
- 9498 - BHARTI Airtel Ltd.: 509
- 47890 - Unmanaged Ltd: 429
- 16276 - OVH SAS: 345
- 131427 - AOHOAVIET: 170

**Source IP Addresses:**
- 59.145.41.149: 509
- 165.227.118.67: 429
- 139.59.20.224: 390
- 51.75.200.154: 345
- 170.64.152.98: 343

**Country to Port Mapping:**
- Australia:
  - 22: 62
  - 2222: 2
- France:
  - 22: 68
  - 3128: 2
  - 4195: 2
  - 4331: 2
  - 4333: 2
- India:
  - 445: 509
  - 22: 115
  - 45737: 56
  - 23: 1
- Romania:
  - 22: 38
  - 14891: 2
  - 16148: 2
  - 16367: 2
  - 17233: 2
- United States:
  - 22: 157
  - 5902: 102
  - 5903: 50
  - 5901: 48
  - 1143: 39

**CVEs Exploited:**
- CVE-2024-14007: 3

**Usernames:**
- root: 248
- admin: 59
- test: 37
- user: 15
- oracle: 14
- ubuntu: 13
- guest: 10
- postgres: 9
- apache: 8
- jenkins: 8

**Passwords:**
- 123456: 30
- 1234: 21
- 12345678: 20
- 123: 18
- password: 17

**OS Distribution:**
- Linux 2.2.x-3.x: 10960
- Windows NT kernel: 5141
- Linux 2.2.x-3.x (barebone): 185
- Windows NT kernel 5.x: 136
- Linux 2.2.x-3.x (no timestamps): 89

**Hyper-aggressive IPs:**
- 59.145.41.149: 509
- 165.227.118.67: 429
- 139.59.20.224: 390
- 51.75.200.154: 345
- 170.64.152.98: 343
