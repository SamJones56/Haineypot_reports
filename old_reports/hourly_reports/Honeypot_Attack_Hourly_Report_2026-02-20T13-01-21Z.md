
# Honeypot Attack Report - 2026-02-20T13:00:25Z

## Executive Summary:
- **High Attack Volume:** A total of 7,470 attacks were observed in the past hour, with a significant concentration from a single Russian IP address.
- **Dominant Attacker:** A single IP address, 83.219.7.170, originating from Rostelecom in Russia, was responsible for 2,828 attacks, constituting over 37% of the total volume. A second IP, 103.133.122.38 from India, launched 1,441 attacks.
- **Primary Attack Vector:** The most frequent alert signature was "GPL INFO VNC server response" with 2,226 instances, indicating widespread reconnaissance or attempted exploitation of VNC services.
- **Geographic Concentration:** Attacks are globally distributed but heavily concentrated from Russia (2,832) and India (1,443), which together account for over 57% of all attacks.
- **Credential Stuffing:** Brute-force attempts were common, with "root" (53 attempts) being the most targeted username and "123456" (25 attempts) the most common password.
- **Operating System Landscape:** The attacking systems are predominantly Windows and Linux based, with "Windows NT kernel" and "Linux 2.2.x-3.x" being the most frequently identified operating systems.

## Detailed Analysis:

### Total Attacks:
- 7,470

### Top Attacking Countries:
- Russia: 2832
- India: 1443
- Germany: 844
- United Kingdom: 595
- Netherlands: 533

### Notable IP Reputations:
- known attacker: 882
- mass scanner: 217
- bot, crawler: 1

### Common Alert Categories:
- Misc activity: 2392
- Generic Protocol Command Decode: 464
- Misc Attack: 408
- Attempted Information Leak: 76
- Potentially Bad Traffic: 32

### Alert Signatures:
- 2100560, GPL INFO VNC server response: 2226
- 2200003, SURICATA IPv4 truncated packet: 115
- 2200122, SURICATA AF-PACKET truncated packet: 115
- 2402000, ET DROP Dshield Block Listed Source group 1: 98
- 2001978, ET INFO SSH session in progress on Expected Port: 71

### ASN Information:
- ASN 12389, Rostelecom: 2828
- ASN 14061, DigitalOcean, LLC: 1865
- ASN 138277, Radinet Info Solutions Private Limited: 1441
- ASN 209334, Modat B.V.: 227
- ASN 213412, ONYPHE SAS: 134

### Source IP Addresses:
- 83.219.7.170: 2828
- 103.133.122.38: 1441
- 167.99.218.227: 496
- 206.189.61.203: 420
- 206.81.21.204: 400

### Country to Port Mapping:
- **Germany**
  - 22: 164
  - 1117: 4
  - 10443: 4
  - 50057: 4
  - 80: 3
- **India**
  - 445: 1441
  - 25567: 1
  - 25568: 1
- **Netherlands**
  - 22: 96
  - 9100: 8
  - 17001: 8
  - 80: 5
  - 3306: 5
- **Russia**
  - 445: 2828
  - 21: 1
  - 80: 1
  - 1433: 1
  - 9401: 1
- **United Kingdom**
  - 22: 90
  - 3601: 4
  - 8993: 4
  - 5432: 3
  - 80: 2

### CVEs Exploited:
- CVE-2023-46604 CVE-2023-46604 CVE-2023-46604: 4
- CVE-2024-14007 CVE-2024-14007: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2025-55182 CVE-2025-55182: 2

### Usernames:
- root: 53
- administrator: 29
- guest: 29
- rosa: 26
- test: 22
- hadoop: 20
- nagios: 20
- zabbix: 20
- ansible: 17
- admin: 16

### Passwords:
- 123456: 25
- 12345: 23
- 123456789: 23
- password: 23
- welcome: 22

### OS Distribution:
- Windows NT kernel: 16231
- Linux 2.2.x-3.x: 15741
- Windows NT kernel 5.x: 10500
- Linux 2.2.x-3.x (barebone): 205
- Linux 2.2.x-3.x (no timestamps): 91

### Hyper-aggressive IPs:
- 83.219.7.170: 2828
- 103.133.122.38: 1441
