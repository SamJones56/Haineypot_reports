# Honeypot Attack Report - 2026-02-21T00:30:21Z

## Executive Summary:
- **High Attack Volume:** The honeypot network observed a total of 161,220 attacks in the past 24 hours.
- **Dominant Attacker:** A single IP address, 45.175.157.3, originating from Paraguay and associated with AS267837 (Vicente Sosa Peralta), was responsible for a significant portion of the attacks, with 35,782 documented events. This IP is considered hyper-aggressive.
- **Geographic Distribution:** Attacks were geographically distributed, with the top 5 attacking countries being Paraguay, the United States, Vietnam, India, and Germany.
- **Common Attack Vectors:** The most common alert categories were "Generic Protocol Command Decode" and "Misc activity", with "GPL INFO VNC server response" being the most frequent alert signature.
- **Credential Stuffing:** Brute-force attempts were prevalent, with "root" being the most targeted username and "123456" and "password" as the most common passwords.
- **Operating Systems:** The attacking systems were predominantly identified as Windows and Linux based systems.

## Detailed Analysis:

**Total Attacks:**
- 161,220

**Top Attacking Countries:**
- Paraguay: 35,782
- United States: 23,384
- Vietnam: 14,494
- India: 11,546
- Germany: 10,464

**Notable IP Reputations:**
- known attacker: 46,181
- mass scanner: 4,660
- bot, crawler: 26
- tor exit node: 18
- compromised: 11

**Common Alert Categories:**
- Generic Protocol Command Decode: 56,308
- Misc activity: 41,066
- Misc Attack: 9,134
- Attempted Administrator Privilege Gain: 3,039
- Attempted Information Leak: 2,693

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 37,192
- 2200003 - SURICATA IPv4 truncated packet: 24,865
- 2200122 - SURICATA AF-PACKET truncated packet: 24,865
- 2024766 - ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2,594
- 2402000 - ET DROP Dshield Block Listed Source group 1: 2,571

**ASN Information:**
- 267837, Vicente Sosa Peralta: 35,782
- 14061, DigitalOcean, LLC: 26,238
- 131414, Long Van Soft Solution JSC: 10,976
- 396982, Google LLC: 5,400
- 39392, SH.cz s.r.o.: 4,995

**Source IP Addresses:**
- 45.175.157.3: 35,782
- 103.237.145.16: 10,976
- 88.86.119.38: 4,995
- 4.145.113.4: 3,981
- 122.180.29.138: 3,157

**Country to Port Mapping:**
- **Germany**
  - 22: 1858
  - 80: 85
  - 9100: 24
  - 5038: 14
  - 8888: 11
- **India**
  - 445: 7621
  - 22: 707
  - 23: 141
  - 2323: 25
  - 19700: 8
- **Paraguay**
  - 22: 7156
  - 2222: 1
- **United States**
  - 445: 1706
  - 22: 667
  - 80: 367
  - 8728: 253
  - 25: 159
- **Vietnam**
  - 445: 3149
  - 22: 2256
  - 19800: 8
  - 9009: 7
  - 9588: 7

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 73
- CVE-2006-2369: 58
- CVE-2021-3449 CVE-2021-3449: 33
- CVE-2025-55182 CVE-2025-55182: 28
- CVE-2019-11500 CVE-2019-11500: 27

**Usernames:**
- root: 11,029
- admin: 586
- sa: 376
- postgres: 267
- user: 249
- ubuntu: 235
- test: 202
- oracle: 192
- guest: 170
- sol: 138

**Passwords:**
- 123456: 389
- password: 340
- : 264
- 12345: 208
- 1234: 203

**OS Distribution:**
- Windows NT kernel: 361,431
- Linux 2.2.x-3.x: 294,813
- Windows NT kernel 5.x: 168,020
- Linux 2.2.x-3.x (barebone): 9,026
- Linux 2.2.x-3.x (no timestamps): 3,940

**Hyper-aggressive IPs:**
- 45.175.157.3: 35,782
