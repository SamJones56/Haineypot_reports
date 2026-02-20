# Honeypot Situation Report

**Report Generation Time:** 2026-02-20T21:05:43Z
**Timeframe:** 2026-02-20T20:55:43Z to 2026-02-20T21:05:43Z

## 1. Executive Summary

This report summarizes the threat landscape observed across our honeypot network over the past 10 minutes. A total of 1,967 attacks were detected, with a significant majority originating from Paraguay. The most active attacker IP was 45.175.157.3, associated with the ASN "Vicente Sosa Peralta". The most common alert signature was related to VNC server responses, and "root" was the most frequently used username in brute-force attempts.

## 2. Key Findings

*   **Total Attacks:** 1,967
*   **Top Attacking Country:** Paraguay (1,615 attacks)
*   **Top Attacker IP:** 45.175.157.3 (1,629 attacks)
*   **Top Attacker ASN:** AS267837 - Vicente Sosa Peralta (1,629 attacks)
*   **Most Common Alert:** GPL INFO VNC server response (40 alerts)
*   **Most Common Username:** `root` (330 attempts)

## 3. Detailed Analysis

### 3.1. Geographic Distribution of Attacks

| Country       | Attack Count |
| :------------ | :----------- |
| Paraguay      | 1,615        |
| United States | 101          |
| Australia     | 65           |
| Germany       | 60           |
| Romania       | 35           |

### 3.2. Top Attacker Source IPs

| Source IP         | Attack Count |
| :---------------- | :----------- |
| 45.175.157.3      | 1,629        |
| 134.199.171.153   | 65           |
| 178.20.210.32     | 50           |
| 188.166.100.4     | 25           |
| 2.57.122.210      | 25           |
| 86.54.24.29       | 20           |
| 46.32.191.223     | 12           |
| 165.154.182.72    | 8            |
| 176.65.139.44     | 8            |
| 185.242.226.46    | 8            |

### 3.3. Top Attacker ASNs

| ASN      | Organization Name            | Attack Count |
| :------- | :--------------------------- | :----------- |
| 267837   | Vicente Sosa Peralta         | 1,629        |
| 14061    | DigitalOcean, LLC            | 95           |
| 210006   | Shereverov Marat Ahmedovich  | 50           |
| 47890    | Unmanaged Ltd                | 45           |
| 396982   | Google LLC                   | 29           |
| 208885   | Noyobzoda Faridduni Saidilhom| 20           |
| 135377   | UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 15           |
| 202425   | IP Volume inc                | 14           |
| 203622   | GSP LLC                      | 12           |
| 213412   | ONYPHE SAS                   | 10           |

### 3.4. Top Alert Signatures

| Signature ID | Signature                                     | Alert Count |
| :----------- | :-------------------------------------------- | :---------- |
| 2100560      | GPL INFO VNC server response                  | 40          |
| 2228000      | SURICATA SSH invalid banner                   | 26          |
| 2200003      | SURICATA IPv4 truncated packet                | 23          |
| 2200122      | SURICATA AF-PACKET truncated packet           | 23          |
| 2001978      | ET INFO SSH session in progress on Expected Port | 12          |
| 2001984      | ET INFO SSH session in progress on Unusual Port | 12          |
| 2210048      | SURICATA STREAM reassembly sequence GAP -- missing packet(s) | 11          |
| 2402000      | ET DROP Dshield Block Listed Source group 1   | 10          |
| 2009582      | ET SCAN NMAP -sS window 1024                  | 7           |
| 2038967      | ET INFO SSH-2.0-Go version string Observed in Network Traffic | 7           |

### 3.5. Credentials Analysis

#### 3.5.1. Top Usernames

| Username | Attempt Count |
| :------- | :------------ |
| root     | 330           |
| oracle   | 11            |
| admin    | 5             |
| solana   | 4             |
| postgres | 3             |
| ubnt     | 2             |
| RPM      | 1             |
| node     | 1             |
| pi       | 1             |
| sol      | 1             |

#### 3.5.2. Top Passwords

| Password      | Attempt Count |
| :------------ | :------------ |
| password      | 2             |
| test          | 2             |
| validator     | 2             |
| !@#$%^        | 1             |
| !QAZ2wsx      | 1             |
| 0.123456789   | 1             |
| 00000000a     | 1             |
| 000000aa      | 1             |
| 00009999      | 1             |
| 000123456     | 1             |

## 4. Conclusion

The data from the last 10 minutes indicates a high volume of automated attacks, likely from a single compromised network in Paraguay. The focus on VNC and SSH, along with common usernames like "root", suggests widespread scanning and brute-force attempts targeting common services and default credentials.

---
**End of Report**