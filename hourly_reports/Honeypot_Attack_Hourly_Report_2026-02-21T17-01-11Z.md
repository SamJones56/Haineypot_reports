# Honeypot Attack Report - 2026-02-21T17:00:15Z

## Executive Summary:
- **High Attack Volume**: A total of 5336 attacks were observed in the last hour, with a significant concentration from Australia (3005 attacks).
- **Dominant Attacker**: The IP address 170.64.225.183, originating from Australia and associated with DigitalOcean, was responsible for the majority of the attacks (3005).
- **Common Attack Vectors**: The most frequent alert category was "Generic Protocol Command Decode" (4171 instances), with "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet" being the most common signatures.
- **Credential Stuffing**: Brute-force attempts were prevalent, with "root" and "admin" as the most common usernames, and "123456" as the most common password.
- **Exploitation Attempts**: Several CVEs were targeted, including CVE-2025-55182 and CVE-2024-14007.
- **Attacker OS**: The dominant operating systems of the attackers were identified as Linux 2.2.x-3.x and Windows NT kernel.

## Detailed Analysis:

**Total Attacks**:
- 5336

**Top Attacking Countries**:
- Australia: 3005
- United States: 928
- Germany: 425
- Vietnam: 250
- Canada: 135

**Notable IP Reputations**:
- known attacker: 1525
- mass scanner: 99
- bot, crawler: 2

**Common Alert Categories**:
- Generic Protocol Command Decode: 4171
- Misc activity: 424
- Misc Attack: 309
- Attempted Information Leak: 95
- Potentially Bad Traffic: 9

**Alert Signatures**:
- 2200003, SURICATA IPv4 truncated packet: 1939
- 2200122, SURICATA AF-PACKET truncated packet: 1939
- 2100560, GPL INFO VNC server response: 224
- 2228000, SURICATA SSH invalid banner: 189
- 2001984, ET INFO SSH session in progress on Unusual Port: 84

**ASN Information**:
- 14061, DigitalOcean, LLC: 3247
- 210006, Shereverov Marat Ahmedovich: 365
- 131427, AOHOAVIET: 250
- 47890, Unmanaged Ltd: 216
- 202425, IP Volume inc: 144

**Source IP Addresses**:
- 170.64.225.183: 3005
- 178.20.210.32: 365
- 103.53.231.159: 250
- 129.212.184.194: 114
- 113.230.94.250: 72

**Country to Port Mapping**:
- Australia
  - 22: 600
- Canada
  - 8728: 3
  - 8525: 2
  - 9153: 2
  - 20002: 2
  - 30005: 2
- Germany
  - 22: 75
  - 5832: 4
  - 8007: 4
  - 9898: 4
  - 9929: 4
- United States
  - 5902: 114
  - 9093: 57
  - 5901: 54
  - 1080: 39
  - 3000: 10
- Vietnam
  - 22: 50

**CVEs Exploited**:
- CVE-2025-55182 CVE-2025-55182: 8
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 2

**Usernames**:
- root: 143
- admin: 34
- user: 18
- deploy: 12
- alex: 11
- test: 10
- ubuntu: 10
- christopher: 8
- kevin: 8
- minecraft: 8

**Passwords**:
- 123456: 120
- 123: 29
- 12345678: 24
- 1234: 22
- password: 18

**OS Distribution**:
- Linux 2.2.x-3.x: 14937
- Windows NT kernel: 10578
- Linux 2.2.x-3.x (barebone): 314
- Windows NT kernel 5.x: 178
- Linux 2.2.x-3.x (no timestamps): 255

**Hyper-aggressive IPs**:
- 170.64.225.183: 3005
- 178.20.210.32: 365
- 103.53.231.159: 250
- 129.212.184.194: 114
