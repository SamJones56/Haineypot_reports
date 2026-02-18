# Honeypot Attack Report - 2026-02-18T21:05:52Z

## Executive Summary:
- **Total Attacks**: There were 2,763 attacks recorded in the past hour.
- **Dominant Attacker**: The United States was the top attacking country with 1,479 attacks, followed by Thailand with 560.
- **Top Signature**: The most frequent alert signature was "GPL INFO VNC server response" (ID: 2100560) with 1,534 occurrences.
- **Hyper-aggressive IPs**: The IP address 110.49.3.20, associated with AIS Fibre in Thailand, was the most active, with 566 attacks.
- **Credential Stuffing**: Common usernames such as 'root', 'ubuntu', and 'admin' were frequently used in attacks.
- **Operating Systems**: The majority of attacks originated from systems identified as Linux 2.2.x-3.x.

## Detailed Analysis:

### Total Attacks:
2,763

### Top Attacking Countries:
- United States: 1479
- Thailand: 560
- China: 164
- India: 93
- Germany: 73

### Notable IP Reputations:
- known attacker: 536
- mass scanner: 89

### Common Alert Categories:
- Misc activity: 1606
- Generic Protocol Command Decode: 525
- Misc Attack: 172
- Potentially Bad Traffic: 61
- Attempted Information Leak: 54

### Alert Signatures:
- ID: 2100560, Signature: GPL INFO VNC server response, Count: 1534
- ID: 2200122, Signature: SURICATA AF-PACKET truncated packet, Count: 109
- ID: 2200003, Signature: SURICATA IPv4 truncated packet, Count: 108
- ID: 2210041, Signature: SURICATA STREAM RST recv but no session, Count: 81
- ID: 2210051, Signature: SURICATA STREAM Packet with broken ack, Count: 80

### ASN Information:
- ASN: 14061, Organization: DigitalOcean, LLC, Count: 1256
- ASN: 133481, Organization: AIS Fibre, Count: 566
- ASN: 4837, Organization: CHINA UNICOM China169 Backbone, Count: 107
- ASN: 132335, Organization: LEAPSWITCH NETWORKS PRIVATE LIMITED, Count: 79
- ASN: 47890, Organization: Unmanaged Ltd, Count: 67

### Source IP Addresses:
- 110.49.3.20: 566
- 129.212.183.188: 459
- 167.71.98.228: 339
- 137.184.211.127: 307
- 103.172.92.103: 79

### Country to Port Mapping:
#### China:
- 30003: 101
- 1433: 47
- 81: 6
#### Germany:
- 22: 10
- 14707: 4
- 30396: 4
#### India:
- 8728: 14
- 445: 13
- 22: 7
#### Thailand:
- 445: 577
#### United States:
- 22: 217
- 3388: 39
- 15672: 35

### CVEs Exploited:
- CVE-2021-3449: 2
- CVE-2019-11500: 1
- CVE-2024-14007: 1
- CVE-2025-55182: 1

### Usernames:
- root: 57
- ubuntu: 44
- admin: 41
- sa: 41
- centos: 11
- apache: 9
- ftp: 9
- mysql: 9
- nginx: 9
- oracle: 9

### Passwords:
- password: 19
- qwerty: 18
- 123456: 17
- admin: 13
- 1234: 8

### OS Distribution:
- Linux 2.2.x-3.x: 10524
- ???: 3309
- Windows 7 or 8: 601
- Linux 3.11 and newer: 119
- Linux 2.2.x-3.x (barebone): 116

### Hyper-aggressive IPs:
- 110.49.3.20: 566
- 129.212.183.188: 459
- 167.71.98.228: 339
- 137.184.211.127: 307
