# Honeypot Attack Report - 2026-02-20T19:00:23Z

## Executive Summary:
- **High Volume of Attacks:** A total of 7,957 attacks were observed in the past hour.
- **Dominant Actors:** Vietnam and India were the top attacking countries, with a significant number of attacks originating from Viettel Group (ASN 7552) and Bharti Airtel Ltd. (ASN 24560).
- **Hyper-aggressive IPs:** Two IPs, 116.96.45.105 (Vietnam) and 122.180.29.138 (India), were responsible for a large portion of the attack volume, with 2,380 and 1,936 attacks respectively.
- **Common Attack Vectors:** The most common alert category was "Generic Protocol Command Decode," with a high number of "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet" alerts. Port 445 was a primary target from Vietnam and India.
- **Credential Stuffing:** Common usernames like "root," "sa," and "postgres" were frequently used in brute-force attempts.
- **Exploitation Attempts:** Low numbers of exploitation attempts for CVE-2024-14007 and CVE-2025-55182 were observed.

## Detailed Analysis:

**Total Attacks:**
- 7957

**Top Attacking Countries:**
- Vietnam: 2390
- India: 1941
- United Kingdom: 845
- United States: 704
- France: 427

**Notable IP Reputations:**
- known attacker: 2054
- mass scanner: 121
- tor exit node: 2

**Common Alert Categories:**
- Generic Protocol Command Decode: 4901
- Misc Attack: 311
- Misc activity: 154
- Attempted Information Leak: 84
- Potentially Bad Traffic: 68

**Alert Signatures:**
- 2200003 - SURICATA IPv4 truncated packet: 2361
- 2200122 - SURICATA AF-PACKET truncated packet: 2361
- 2402000 - ET DROP Dshield Block Listed Source group 1: 90
- 2001978 - ET INFO SSH session in progress on Expected Port: 84
- 2010935 - ET SCAN Suspicious inbound to MSSQL port 1433: 48

**ASN Information:**
- 7552, Viettel Group: 2380
- 24560, Bharti Airtel Ltd., Telemedia Services: 1936
- 14061, DigitalOcean, LLC: 1219
- 211590, Bucklog SARL: 392
- 396982, Google LLC: 344

**Source IP Addresses:**
- 116.96.45.105: 2380
- 122.180.29.138: 1936
- 159.65.24.244: 415
- 143.198.33.195: 409
- 185.177.72.52: 387

**Country to Port Mapping:**
- **France**
  - 80: 392
  - 3128: 3
  - 2082: 2
  - 2575: 2
  - 3089: 2
- **India**
  - 445: 1936
  - 22: 2
  - 25568: 1
- **United Kingdom**
  - 22: 154
  - 10809: 10
  - 50504: 8
  - 2086: 2
  - 8000: 2
- **United States**
  - 8008: 43
  - 1294: 18
  - 8728: 14
  - 42313: 14
  - 2088: 13
- **Vietnam**
  - 445: 2380
  - 22: 2

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2025-55182 CVE-2025-55182: 1

**Usernames:**
- root: 113
- sa: 41
- postgres: 34
- oracle: 27
- admin: 25
- solv: 12
- ubuntu: 10
- sol: 9
- sshd: 9
- user: 7

**Passwords:**
- password: 25
- 123: 11
- 123456: 11
- www-data: 7
- 12345: 6

**OS Distribution:**
- Windows NT kernel: 16999
- Linux 2.2.x-3.x: 15200
- Linux 2.2.x-3.x (barebone): 435
- Linux 2.2.x-3.x (no timestamps): 361
- Windows NT kernel 5.x: 79

**Hyper-aggressive IPs:**
- 116.96.45.105: 2380
- 122.180.29.138: 1936
