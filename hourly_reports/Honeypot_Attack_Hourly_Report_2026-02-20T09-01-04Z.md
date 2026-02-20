# Honeypot Attack Report - 2026-02-20T09:00:16Z

## Executive Summary:
- **High Attack Volume:** A total of 4,034 attacks were observed in the past hour, indicating a significant level of malicious activity.
- **Geographic Distribution:** Attacks are globally distributed, with Germany (726) and the United States (708) being the most prominent sources. A noteworthy concentration of attacks targeting port 445 originated from Russia.
- **Dominant Attacker Infrastructure:** A large portion of attacks (1,089) originated from AS14061 (DigitalOcean, LLC), a common cloud provider. IP addresses classified as "known attacker" were responsible for 1,138 attacks.
- **VNC and SMB Focus:** The most frequent alert signature was "GPL INFO VNC server response" with 2,290 instances, suggesting widespread scanning for open VNC servers. Additionally, Russian sources heavily targeted port 445 (SMB).
- **Credential Brute-Forcing:** The most common username attempted was "root" (128 times), and a significant number of attempts (123) used an empty password, indicating low-sophistication brute-force attacks.
- **Hyper-Aggressive IPs:** Four IP addresses exceeded a threshold of 350 attacks each, with the most active being 46.101.240.14 with 395 attacks.

## Detailed Analysis:

**Total Attacks:**
- 4,034

**Top Attacking Countries:**
- Germany: 726
- United States: 708
- Russia: 416
- Singapore: 386
- Australia: 370

**Notable IP Reputations:**
- known attacker: 1,138
- mass scanner: 233
- bot, crawler: 2

**Common Alert Categories:**
- Misc activity: 2,450
- Generic Protocol Command Decode: 1,162
- Misc Attack: 426
- Attempted Information Leak: 77
- Attempted Administrator Privilege Gain: 23

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 2,290
- 2200003 - SURICATA IPv4 truncated packet: 469
- 2200122 - SURICATA AF-PACKET truncated packet: 469
- 2402000 - ET DROP Dshield Block Listed Source group 1: 126
- 2001978 - ET INFO SSH session in progress on Expected Port: 64

**ASN Information:**
- 14061 - DigitalOcean, LLC: 1,089
- 8075 - Microsoft Corporation: 410
- 49724 - JSC Vainah Telecom: 387
- 51852 - Private Layer INC: 214
- 396982 - Google LLC: 213

**Source IP Addresses:**
- 46.101.240.14: 395
- 188.0.175.155: 387
- 4.145.113.4: 383
- 170.64.175.89: 370
- 164.90.185.60: 305

**Country to Port Mapping:**
- **Australia:**
  - 22: 74
- **Germany:**
  - 22: 140
  - 11434: 6
  - 4032: 4
- **Russia:**
  - 445: 387
  - 28017: 25
  - 1433: 2
- **Singapore:**
  - 5902: 39
  - 5903: 39
  - 5905: 39
- **United States:**
  - 50030: 16
  - 2082: 11
  - 3041: 10

**CVEs Exploited:**
- CVE-2024-14007: 4
- CVE-2020-14882 CVE-2020-14883: 1
- CVE-2023-26801: 1
- CVE-2025-55182: 1

**Usernames:**
- root: 128
- ubuntu: 27
- guest: 21
- centos: 18
- test: 18
- debian: 17
- dev: 11
- developer: 11
- elastic: 11
- postgres: 11

**Passwords:**
- : 123
- 1234: 18
- 123: 12
- 1q2w3e4r: 12
- password1: 12

**OS Distribution:**
- Windows NT kernel: 17,114
- Linux 2.2.x-3.x: 15,769
- Windows NT kernel 5.x: 9,539
- Linux 2.2.x-3.x (barebone): 359
- Linux 2.2.x-3.x (no timestamps): 126

**Hyper-aggressive IPs:**
- 46.101.240.14: 395
- 188.0.175.155: 387
- 4.145.113.4: 383
- 170.64.175.89: 370
