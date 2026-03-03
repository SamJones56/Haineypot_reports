Honeypot Attack Summary Report – 2026-02-21T00:47:02Z

## Metadata
- **Report Generation Time:** 2026-02-21T00:47:02Z
- **Timeframe Covered:** 2026-02-20T00:30:21Z - 2026-02-21T00:30:21Z
- **Files Used:**
    - `/home/user/Haineypot/reports/daily_reports/Honeypot_Attack_Daily_Report_2026-02-21T00-31-10Z.md`

## Executive Summary
The honeypot network recorded 161,220 attacks in the last 24-hour period. A hyper-aggressive actor, **45.175.157.3**, associated with **AS267837 (Vicente Sosa Peralta)** in Paraguay, was responsible for 35,782 (22%) of the total events, primarily targeting SSH. A significant threat observed was the attempted exploitation using the **DoublePulsar backdoor**, commonly associated with the EternalBlue exploit, indicating sophisticated attack chains targeting SMB services. Credential stuffing attacks remain prevalent, with `root` being the primary target. The top sources of attacks originated from Paraguay, the United States, Vietnam, India, and Germany.

## Detailed Analysis

### Our IPs
- tpot-hive-ny: 134.199.242.175

### Attacks by Honeypot
| Honeypot | Total Attacks |
|---|---|
| tpot-hive-ny | 161,220 |

### Top Source Countries
| Country | Total Attacks |
|---|---|
| Paraguay | 35,782 |
| United States | 23,384 |
| Vietnam | 14,494 |
| India | 11,546 |
| Germany | 10,464 |

### Top Attacking IPs
| IP Address | Total Attacks |
|---|---|
| 45.175.157.3 | 35,782 |
| 103.237.145.16 | 10,976 |
| 88.86.119.38 | 4,995 |
| 4.145.113.4 | 3,981 |
| 122.180.29.138 | 3,157 |

### Top Targeted Ports/Protocols
| Country | Port | Protocol | Attacks |
|---|---|---|---|
| India | 445 | SMB | 7,621 |
| Paraguay | 22 | SSH | 7,156 |
| Vietnam | 445 | SMB | 3,149 |
| Vietnam | 22 | SSH | 2,256 |
| Germany | 22 | SSH | 1,858 |
| United States | 445 | SMB | 1,706 |
| United States | 22 | SSH | 667 |

### Most Common CVEs (LIST ALL)
| CVE ID | Count |
|---|---|
| CVE-2024-14007 | 73 |
| CVE-2006-2369 | 58 |
| CVE-2021-3449 | 33 |
| CVE-2025-55182 | 28 |
| CVE-2019-11500 | 27 |

### Commands Attempted
(No specific commands were detailed in the aggregated report)

### Signatures Triggered
| Signature | Count |
|---|---|
| GPL INFO VNC server response | 37,192 |
| SURICATA IPv4 truncated packet | 24,865 |
| SURICATA AF-PACKET truncated packet | 24,865 |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 2,594 |
| ET DROP Dshield Block Listed Source group 1 | 2,571 |

### Users / Login Attempts
| Username | Attempts |
|---|---|
| root | 11,029 |
| admin | 586 |
| sa | 376 |
| postgres | 267 |
| user | 249 |

| Password | Attempts |
|---|---|
| 123456 | 389 |
| password | 340 |
| (blank) | 264 |
| 12345 | 208 |
| 1234 | 203 |

### Files Uploaded/Downloaded
(No file transfer events were detailed in the aggregated report)

### HTTP User-Agents
(No HTTP User-Agent data was available in the aggregated report)

### SSH Clients and Servers
(No specific SSH client/server version data was available in the aggregated report)

### Top Attacker AS Organizations
| ASN | Organization | Total Attacks |
|---|---|---|
| 267837 | Vicente Sosa Peralta | 35,782 |
| 14061 | DigitalOcean, LLC | 26,238 |
| 131414 | Long Van Soft Solution JSC | 10,976 |
| 396982 | Google LLC | 5,400 |
| 39392 | SH.cz s.r.o. | 4,995 |

## OSINT Section

### OSINT on High-Frequency IPs
- **45.175.157.3:** This IP is the single most aggressive actor in this period. It originates from Paraguay and is associated with AS267837. OSINT confirms the ASN is a Cable/DSL/ISP provider named "Vicente Sosa Peralta" (operating as CDENET) located in Paraguay. The ASN has prior associations with spamming activities, suggesting a potential source of compromised or malicious residential/business clients.

### OSINT on CVEs
- **CVE-2024-14007:** An authentication bypass vulnerability in TVT NVMS-9000 DVR/NVR devices. Allows an unauthenticated attacker to execute privileged commands. A public exploit is available.
- **CVE-2025-55182:** Reported as "React2Shell," a critical (CVSS 10.0) unauthenticated RCE in the `react-server` package. The future-dated CVE identifier suggests this may be a misattribution by a security tool, a pre-assigned CVE, or a custom signature. Given its reported severity and widespread exploitation, it represents a significant threat if accurate.
- **CVE-2019-11500:** A critical out-of-bounds write vulnerability in Dovecot email server software, which can lead to denial of service, data leakage, or arbitrary code execution.
- **DoublePulsar Signature:** The signature "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" is highly significant. DoublePulsar is a kernel-mode backdoor developed by the NSA and leaked by The Shadow Brokers. It is typically installed after a system is compromised by an exploit like EternalBlue (targeting SMB). Its presence indicates a severe, successful compromise attempt aiming to establish persistent control. This correlates with the high volume of attacks targeting port 445 (SMB).

## Key Observations and Anomalies
- **Hyper-aggressive Actor:** The IP **45.175.157.3** from Paraguay showed anomalous aggression, accounting for 22% of all attack traffic. This activity appears to be from a single source and is not typical background noise.
- **Campaign Indicators:** The detection of **DoublePulsar** communication attempts is a strong indicator of a concerted campaign to exploit SMB vulnerabilities, likely related to the MS17-010 (EternalBlue) vulnerability. The high volume of SMB traffic from multiple countries supports this.
- **Infrastructure Reuse:** The ASN **267837 (Vicente Sosa Peralta)** being a residential ISP with a history of spam suggests that the infrastructure is likely a pool of compromised devices rather than a dedicated malicious hosting provider.
- **Unusual CVE:** The presence of **CVE-2025-55182** is an anomaly. While reported as a critical RCE, the 2025 designation warrants further monitoring and verification, as it may represent a new threat or a signature error.

## Unusual Attacker Origins
- **Paraguay:** While not a traditional top-tier source of cyberattacks, Paraguay is the number one origin in this report due entirely to the hyper-aggressive activity from **45.175.157.3** and **AS267837**. This highlights how a single, highly active threat actor can significantly skew geographic statistics.