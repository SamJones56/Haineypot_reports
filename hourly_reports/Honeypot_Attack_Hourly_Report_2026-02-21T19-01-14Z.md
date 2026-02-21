# Honeypot Attack Report - 2026-02-21T19:00:23Z

## Executive Summary:
- **High Attack Volume:** The honeypot network observed a total of 3,495 attacks in the past hour, indicating a significant level of malicious activity.
- **Geographic Concentration:** The majority of attacks originated from the United States, which accounted for 989 of the total attacks. Qatar and Germany were also major sources of attacks, with 527 and 480 attacks respectively.
- **Dominant Attacker:** The IP address 178.153.127.226, associated with ASN 8781 (Ooredoo Q.S.C.) in Qatar, was the most aggressive attacker, responsible for 527 attacks targeting port 445.
- **Common Attack Vectors:** The most frequent alert categories were "Generic Protocol Command Decode" and "Misc activity," suggesting a high volume of reconnaissance and protocol-level attacks. The most common alert signature was "GPL INFO VNC server response," indicating a focus on VNC servers.
- **Credential Stuffing:** Brute-force attempts were prevalent, with "root," "test," and "user" being the most common usernames and "123456," "12345678," and "1234" being the most common passwords.
- **Exploitation Attempts:** While not widespread, there were observed attempts to exploit several vulnerabilities, with CVE-2024-14007 being the most frequent.

## Detailed Analysis:

**Total Attacks:**
- 3,495

**Top Attacking Countries:**
- United States: 989
- Qatar: 527
- Germany: 480
- United Kingdom: 445
- Vietnam: 287

**Notable IP Reputations:**
- known attacker: 1,760
- mass scanner: 92
- bot, crawler: 11

**Common Alert Categories:**
- Generic Protocol Command Decode: 567
- Misc activity: 522
- Misc Attack: 330
- Attempted Information Leak: 57
- Potentially Bad Traffic: 21

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 226
- 2228000 - SURICATA SSH invalid banner: 209
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 100
- 2001984 - ET INFO SSH session in progress on Unusual Port: 99
- 2200003 - SURICATA IPv4 truncated packet: 96

**ASN Information:**
- AS14061 - DigitalOcean, LLC: 656
- AS8781 - Ooredoo Q.S.C.: 527
- AS47890 - Unmanaged Ltd: 470
- AS210006 - Shereverov Marat Ahmedovich: 370
- AS131427 - AOHOAVIET: 280

**Source IP Addresses:**
- 178.153.127.226: 527
- 159.65.24.56: 380
- 178.20.210.32: 370
- 103.53.231.159: 280
- 129.212.184.194: 115

**Country to Port Mapping:**
- **Germany:**
  - 22: 75
  - 6000: 67
  - 57649: 4
  - 8812: 3
  - 9302: 3
- **Qatar:**
  - 445: 527
- **United Kingdom:**
  - 22: 76
  - 5001: 11
  - 3977: 2
  - 5445: 2
  - 8123: 2
- **United States:**
  - 5902: 115
  - 5901: 55
  - 44818: 40
  - 2181: 37
  - 22: 28
- **Vietnam:**
  - 22: 56
  - 9700: 7

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 5
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- root: 32
- test: 24
- user: 24
- guest: 18
- centos: 14
- sol: 14
- admin: 13
- brian: 8
- george: 8
- oracle: 8

**Passwords:**
- 123456: 25
- 12345678: 24
- 1234: 23
- 123: 19
- : 10

**OS Distribution:**
- Linux 2.2.x-3.x: 14694
- Windows NT kernel: 10593
- Linux 2.2.x-3.x (barebone): 339
- Linux 2.2.x-3.x (no timestamps): 341
- Windows NT kernel 5.x: 127

**Hyper-aggressive IPs:**
- 178.153.127.226: 527
- 159.65.24.56: 380
- 178.20.210.32: 370
- 103.53.231.159: 280
