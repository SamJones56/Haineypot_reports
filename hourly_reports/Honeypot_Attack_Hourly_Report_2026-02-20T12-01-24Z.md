# Honeypot Attack Report - 2026-02-20T12:00:25Z

## Executive Summary:
- **High Volume of Attacks:** A total of 5,591 attacks were observed in the past hour.
- **Dominant Attacker:** India was the top attacking country with 1,394 attacks, primarily targeting port 445. The IP address 103.133.122.38 from India was responsible for 1,351 of these attacks.
- **Top ASN:** DigitalOcean, LLC (AS14061) was the most prominent ASN, accounting for 2,332 attacks.
- **Common Alerts:** The most frequent alert signature was "GPL INFO VNC server response" (2,222 occurrences), and the top alert category was "Generic Protocol Command Decode" (3,399 occurrences).
- **Credential Stuffing:** Brute-force attempts were common, with "root" being the most targeted username (87 attempts) and "123456" the most used password (44 attempts).
- **Hyper-Aggressive IPs:** Four IP addresses were identified as hyper-aggressive, each with over 500 attacks.

## Detailed Analysis:

**Total Attacks:**
- 5,591

**Top Attacking Countries:**
- India: 1,394
- Germany: 1,075
- United Kingdom: 770
- Netherlands: 724
- United States: 514

**Notable IP Reputations:**
- known attacker: 1,403
- mass scanner: 218
- bot, crawler: 1

**Common Alert Categories:**
- Generic Protocol Command Decode: 3,399
- Misc activity: 2,492
- Misc Attack: 377
- Attempted Information Leak: 159
- Attempted Administrator Privilege Gain: 45

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 2,222
- 2200003 - SURICATA IPv4 truncated packet: 906
- 2200122 - SURICATA AF-PACKET truncated packet: 906
- 2221010 - SURICATA HTTP unable to match response to request: 673
- 2210051 - SURICATA STREAM Packet with broken ack: 263

**ASN Information:**
- 14061 - DigitalOcean, LLC: 2,332
- 138277 - Radinet Info Solutions Private Limited: 1,351
- 208137 - Feo Prest SRL: 392
- 396982 - Google LLC: 249
- 47890 - Unmanaged Ltd: 208

**Source IP Addresses:**
- 103.133.122.38: 1,351
- 144.126.205.38: 610
- 206.189.61.203: 580
- 167.99.218.227: 569
- 206.81.21.204: 475

**Country to Port Mapping:**
- **Germany**
  - 22: 211
  - 3306: 4
  - 4032: 4
  - 7020: 4
  - 9037: 4
- **India**
  - 445: 1,351
  - 22: 6
- **Netherlands**
  - 22: 114
  - 443: 94
  - 6037: 8
  - 80: 5
  - 5432: 3
- **United Kingdom**
  - 22: 124
  - 3030: 4
  - 4001: 4
  - 4200: 4
  - 5454: 4
- **United States**
  - 8883: 19
  - 25: 17
  - 8728: 14
  - 10000: 14
  - 6379: 11

**CVEs Exploited:**
- CVE-2021-3449: 3
- CVE-2019-11500: 2
- CVE-2024-14007: 2

**Usernames:**
- root: 87
- debian: 49
- oracle: 42
- guest: 33
- mysql: 33
- git: 32
- pi: 29
- newuser: 26
- postgres: 24
- dspace: 20

**Passwords:**
- 123456: 44
- password: 39
- welcome: 35
- 12345: 34
- 123456789: 34

**OS Distribution:**
- Windows NT kernel: 17,619
- Linux 2.2.x-3.x: 16,156
- Windows NT kernel 5.x: 10,107
- Linux 2.2.x-3.x (barebone): 222
- Linux 2.2.x-3.x (no timestamps): 75

**Hyper-aggressive IPs:**
- 103.133.122.38: 1,351
- 144.126.205.38: 610
- 206.189.61.203: 580
- 167.99.218.227: 569
