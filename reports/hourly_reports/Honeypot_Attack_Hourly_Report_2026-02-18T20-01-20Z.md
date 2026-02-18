
# Honeypot Attack Report - 2026-02-18T20:00:34Z

## Executive Summary:
- **High Attack Volume:** Over 3,700 attacks were recorded in the past hour, indicating a significant level of automated scanning and exploitation activity.
- **Geographic Concentration:** Attacks are primarily sourced from North America and Asia, with Canada, the United States, and China being the top three originating countries.
- **Dominant Attacker Profile:** The majority of attacks are launched from IPs associated with known malicious actors and mass scanners, hosted on commercial services like DigitalOcean and Modat B.V.
- **Common Vulnerabilities Targeted:** Attackers are frequently attempting to exploit a mix of recent and older vulnerabilities, including CVE-2024-4577 and CVE-2002-0953.
- **Linux-Based Attacks:** The overwhelming majority of attacks originate from systems running older Linux kernels (2.2.x-3.x).
- **Credential Stuffing:** Brute-force attempts are ongoing, with simple, common passwords like "123456" and "password" being used frequently.

## Detailed Analysis:

- **Total Attacks:** 3,798
- **Top Attacking Countries:** Canada (1,484), United States (913), China (280), Kazakhstan (222), Switzerland (178).
- **Notable IP Reputations:** The majority of attacks came from IPs flagged as "known attacker" (2,483 events) and "mass scanner" (141 events).
- **Common Alert Categories and Signatures:**
    - Categories: "Misc activity" (2,436) and "Generic Protocol Command Decode" (569).
    - Signatures: "GPL INFO VNC server response" (2,326) and "SURICATA IPv4 truncated packet" (171).
- **ASN Information:**
    - AS209334 (Modat B.V.): 1,070 attacks
    - AS14061 (DigitalOcean, LLC): 793 attacks
    - AS48716 (PS Internet Company LLP): 222 attacks
- **Source IPs:**
    - 129.212.183.188: 301 attacks
    - 143.110.221.173: 271 attacks
    - 78.40.108.232: 222 attacks
- **Country to Port Mapping:**
    - Canada: Port 1080 (SOCKS), Port 22 (SSH)
    - United States: Port 22 (SSH), Port 3388
    - China: Port 30003, Port 1433 (MSSQL)
    - Kazakhstan: Port 22 (SSH)
    - Switzerland: Port 5435
- **CVEs Exploited:** CVE-2024-4577, CVE-2002-0953, CVE-2021-41773, CVE-2021-42013, CVE-2024-14007.
- **Usernames & Passwords:**
    - Usernames: Data not available due to a tool error.
    - Passwords: "123456", "password", "12345", "12345678", "123456789".
- **OS Distribution:** "Linux 2.2.x-3.x" was the most common OS signature (19,819 events).
- **Hyper-aggressive IPs:** 129.212.183.188 (301 attacks).
- **Unusual credential patterns:** N/A
- **Attacker signatures/taunts:** N/A
- **Malware/botnet filenames:** N/A
- **Other high-signal deviations:** N/A
