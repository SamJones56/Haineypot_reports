# Honeypot Attack Report - 2026-02-19T19:00:12Z

## Executive Summary:
- **High Attack Volume:** Over 4,212 attacks were observed in the past hour, with the United States and Germany being the most prominent sources of attacks.
- **Dominant Attacker Infrastructure:** DigitalOcean, LLC infrastructure was responsible for the majority of attacks, accounting for over 2,351 incidents.
- **Common Attack Vectors:** The most frequent alert category was "Generic Protocol Command Decode", with "SURICATA IPv4 truncated packet" being the most common signature.
- **Credential Brute-Forcing:** The most common username and password combinations were `root:password` and `admin:123456`, indicating widespread brute-force attempts.
- **Exploitation Attempts:** Several CVEs were observed, with `CVE-2024-14007` being the most frequently targeted.
- **Hyper-aggressive IPs:** A small number of IP addresses were responsible for a large volume of attacks, with four IPs exceeding 300 attacks each.

## Detailed Analysis:

**Total Attacks:**
- 4212

**Top Attacking Countries:**
- United States: 1200
- Germany: 1150
- Australia: 453
- Singapore: 327
- United Kingdom: 293

**Notable IP Reputations:**
- known attacker: 1483
- mass scanner: 165
- bot, crawler: 2

**Common Alert Categories:**
- Generic Protocol Command Decode: 15050
- Misc activity: 2146
- Misc Attack: 366
- Attempted Information Leak: 118
- Potentially Bad Traffic: 13

**Alert Signatures:**
- 2200003 - SURICATA IPv4 truncated packet: 7435
- 2200122 - SURICATA AF-PACKET truncated packet: 7435
- 2100560 - GPL INFO VNC server response: 1968
- 2402000 - ET DROP Dshield Block Listed Source group 1: 102
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 72

**ASN Information:**
- 14061, DigitalOcean, LLC: 2351
- 135377, UCLOUD INFORMATION TECHNOLOGY HK LIMITED: 526
- 8075, Microsoft Corporation: 339
- 396982, Google LLC: 267
- 174, Cogent Communications, LLC: 180

**Source IP Addresses:**
- 207.154.239.37: 393
- 104.248.249.212: 360
- 4.145.113.4: 327
- 165.227.161.214: 319
- 134.199.173.128: 235

**Country to Port Mapping:**
- Australia
  - 22: 87
- Germany
  - 22: 215
  - 50001: 16
  - 9443: 14
- Singapore
  - 5901: 33
  - 5904: 33
  - 5906: 33
- United Kingdom
  - 22: 32
  - 8088: 16
  - 30443: 14
- United States
  - 22: 74
  - 8081: 25
  - 2000: 18

**CVEs Exploited:**
- CVE-2024-14007
- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-2002-0606

**Usernames:**
- root: 131
- admin: 73
- debian: 30
- backup: 26
- daemon: 24
- dev: 23
- user: 22
- test: 19
- administrator: 10
- ansible: 10

**Passwords:**
- password: 27
- 123456: 26
- qwerty: 23
- 12345: 19
- 123456789: 16

**OS Distribution:**
- Linux 2.2.x-3.x: 15849
- Windows NT kernel 5.x: 7787
- Linux 2.2.x-3.x (barebone): 561
- Linux 2.2.x-3.x (no timestamps): 84
- Linux 3.11 and newer: 29

**Hyper-aggressive IPs:**
- 207.154.239.37: 393
- 104.248.249.212: 360
- 4.145.113.4: 327
- 165.227.161.214: 319
