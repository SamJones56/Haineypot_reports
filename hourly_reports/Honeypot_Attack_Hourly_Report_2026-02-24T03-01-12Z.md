# Honeypot Attack Report - 2026-02-24T03:00:29Z

## Executive Summary:
- Over 3,300 attacks were observed in the last hour.
- The United States was the dominant source of attacks, accounting for nearly half of all observed activity.
- DigitalOcean, LLC was the top attacking ASN, responsible for over a third of the attacks.
- The most common alert category was "Generic Protocol Command Decode".
- The most frequent alert signature was "GPL INFO VNC server response".
- The most aggressive IP was 162.243.37.252 with 523 attacks.

## Detailed Analysis:

**Total Attacks:** 3339

**Top Attacking Countries:**
- United States: 1627
- United Kingdom: 497
- Canada: 413
- Romania: 218
- Vietnam: 155

**Notable IP Reputations:**
- known attacker: 1531
- mass scanner: 108

**Common Alert Categories:**
- Generic Protocol Command Decode: 473
- Misc activity: 443
- Misc Attack: 309
- Attempted Information Leak: 76
- Potentially Bad Traffic: 31

**Alert Signatures:**
- 2100560 - GPL INFO VNC server response: 218
- 2228000 - SURICATA SSH invalid banner: 212
- 2001984 - ET INFO SSH session in progress on Unusual Port: 97
- 2402000 - ET DROP Dshield Block Listed Source group 1: 89
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 68

**ASN Information:**
- 14061 - DigitalOcean, LLC: 1295
- 209334 - Modat B.V.: 405
- 47890 - Unmanaged Ltd: 370
- 396982 - Google LLC: 249
- 131427 - AOHOAVIET: 155

**Source IP Addresses:**
- 162.243.37.252: 523
- 157.245.36.181: 458
- 2.57.122.96: 170
- 103.53.231.159: 155
- 129.212.184.194: 113

**Country to Port Mapping:**
- Canada:
    - 8728: 8
    - 19233: 4
    - 50060: 4
    - 6467: 3
    - 9922: 3
- Romania:
    - 22: 36
    - 1960: 2
    - 7940: 2
    - 17810: 2
    - 18649: 2
- United Kingdom:
    - 22: 89
    - 80: 4
    - 8000: 3
    - 8089: 2
    - 23: 1
- United States:
    - 5902: 114
    - 22: 107
    - 1500: 78
    - 5903: 58
    - 5901: 53
- Vietnam:
    - 22: 31

**CVEs Exploited:**
- CVE-2024-14007
- CVE-2023-46604
- CVE-2025-55182
- CVE-2019-11500
- CVE-2021-3449

**Usernames:**
- root: 94
- admin: 47
- daemon: 31
- hadoop: 13
- oracle: 13
- postgres: 13
- test: 13
- zabbix: 13
- mysql: 9
- user: 5

**Passwords:**
- password: 13
- 12345: 11
- 123456789: 11
- 12345678: 10
- 1234: 9

**OS Distribution:**
- Linux 2.2.x-3.x: 11700
- Windows NT kernel: 3081
- Linux 2.2.x-3.x (barebone): 358
- Linux 3.1-3.10: 379
- Linux 3.11 and newer: 246

**Hyper-aggressive IPs:**
- 162.243.37.252: 523
- 157.245.36.181: 458
