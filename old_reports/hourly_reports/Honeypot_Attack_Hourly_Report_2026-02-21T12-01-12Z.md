
# Honeypot Attack Report - 2026-02-21T12:00:17Z

## Executive Summary:
- **Volume:** 2444 attacks were observed in the last hour.
- **Geography:** The United States (508) and Russia (423) were the top attacking countries.
- **Actors:** The most aggressive IP was 82.147.85.17 with 422 attacks, associated with ASN 211860 (Nerushenko Vyacheslav Nikolaevich).
- **Signatures:** "SURICATA SSH invalid banner" (234) and "GPL INFO VNC server response" (226) were the most common alerts.
- **Credentials:** Brute force attempts primarily targeted the 'root' username (119 attempts).
- **Anomalies:** A significant number of attacks (1588) originated from IPs with a "known attacker" reputation.

## Detailed Analysis:

**Total Attacks:**
- 2444

**Top Attacking Countries:**
- United States: 508
- Russia: 423
- Singapore: 380
- Canada: 190
- Vietnam: 186

**Notable IP Reputations:**
- known attacker: 1588
- mass scanner: 116

**Common Alert Categories:**
- Generic Protocol Command Decode: 407
- Misc activity: 396
- Misc Attack: 328
- Attempted Information Leak: 97
- Attempted Administrator Privilege Gain: 22

**Alert Signatures:**
- 2228000, SURICATA SSH invalid banner: 234
- 2100560, GPL INFO VNC server response: 226
- 2001984, ET INFO SSH session in progress on Unusual Port: 107
- 2402000, ET DROP Dshield Block Listed Source group 1: 93
- 2009582, ET SCAN NMAP -sS window 1024: 44

**ASN Information:**
- 211860, Nerushenko Vyacheslav Nikolaevich: 422
- 14061, DigitalOcean, LLC: 384
- 47890, Unmanaged Ltd: 315
- 131427, AOHOAVIET: 186
- 209334, Modat B.V.: 185

**Source IP Addresses:**
- 82.147.85.17: 422
- 128.199.198.62: 376
- 103.53.231.159: 186
- 46.19.137.194: 168
- 2.57.122.96: 98

**Country to Port Mapping:**
- Canada
  - 8728: 5
  - 1060: 2
  - 2694: 2
- Russia
  - 1025: 3
  - 1031: 1
  - 1100: 1
- Singapore
  - 22: 75
  - 2095: 3
  - 5038: 1
- United States
  - 1723: 30
  - 8728: 13
  - 17000: 12
- Vietnam
  - 22: 37

**CVEs Exploited:**
- CVE-2024-14007: 4
- CVE-2025-3248: 1
- CVE-2025-55182: 1

**Usernames:**
- root: 119
- ubuntu: 3
- eth: 2
- postgres: 2
- sol: 2
- solana: 2
- curved: 1
- eigen: 1
- eigenlayer: 1
- ethereum: 1

**Passwords:**
- eigen: 3
- eigenlayer: 3
- : 2
- 000000: 2
- 111111: 2

**OS Distribution:**
- Linux 2.2.x-3.x: 13669
- Windows NT kernel: 12156
- Linux 2.2.x-3.x (barebone): 241
- Windows NT kernel 5.x: 140
- Linux 2.2.x-3.x (no timestamps): 158

**Hyper-aggressive IPs:**
- 82.147.85.17: 422
- 128.199.198.62: 376
