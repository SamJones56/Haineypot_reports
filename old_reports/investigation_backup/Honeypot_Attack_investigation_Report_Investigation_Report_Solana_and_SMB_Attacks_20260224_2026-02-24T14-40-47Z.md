# Investigation Report: Targeted Blockchain Infrastructure Attacks and Automated Service Reconnaissance
**Date:** 2026-02-24
**Timeframe:** 14:10:01Z to 14:40:01Z (Last 30 Minutes)
**Investigator:** Senior Cyber Threat Investigator
**Subject IP(s):** 80.94.92.182 (Romania), 189.87.56.210 (Brazil), 201.249.74.42 (Venezuela), 129.212.184.194 (USA)

---

## 1. Executive Summary
During the specified 30-minute investigative window, the honeypot network (tpot-hive-ny) observed a total of 4,973 attack events. The investigation identified two primary threads of activity: a highly targeted credential spraying campaign focusing on Solana blockchain infrastructure and massive automated SMB reconnaissance originating from South American ISP infrastructure.

## 2. Lead 1: Targeted Solana Infrastructure Attacks
### Observation
A Romanian IP address, **80.94.92.182** (Unmanaged Ltd / TECHOFF SRV), was observed conducting persistent SSH credential spraying attempts.

### Analytical Findings
- **Username Pattern:** The actor used specific usernames including `solana`, `sol`, and `solv`.
- **Credential Samples:** Failed attempts included `solana:p@ssw0rd`, `solana:pa2ssw0rd`, and `solana:!@#$%^`.
- **Infrastructure Context:** OSINT correlation confirms this IP has a 100% abuse score and is actively reported for targeting Solana validator nodes and RPC infrastructure.
- **Hypothesis:** This represents a coordinated attempt by a threat actor to compromise the underlying Linux servers powering the Solana network, likely to steal sensitive keys or disrupt node operations.
- **Confidence Level:** High.

## 3. Lead 2: High-Volume South American SMB Reconnaissance
### Observation
Significant traffic volume (over 70% of total events) originated from two South American IPs targeting port 445 (SMB).
- **189.87.56.210** (CLARO S.A., Brazil): 2,693 hits.
- **201.249.74.42** (CANTV, Venezuela): 834 hits.

### Analytical Findings
- **Behavioral Analysis:** Suricata and Dionaea logs show aggressive protocol negotiation (`SMB1_COMMAND_NEGOTIATE_PROTOCOL`). 
- **Reconnaissance Indicators:** The Venezuelan IP specifically attempted to connect to the `IPC$` share, a classic indicator of share enumeration and lateral movement preparation.
- **Hypothesis:** These IPs are likely compromised nodes in a botnet engaged in global scanning for vulnerable SMB services (e.g., MS17-010). The high frequency suggests automated worm-like behavior.
- **Confidence Level:** High.

## 4. Lead 3: US-Based VNC Probing
### Observation
IP **129.212.184.194** (DigitalOcean, USA) was observed probing multiple VNC ports (5902–5905).

### Analytical Findings
- **Technical Profile:** P0f identifies the source as a Linux system (2.2.x-3.x).
- **Significance:** Cloud-based infrastructure (DigitalOcean) is being used to scan other cloud networks for exposed remote desktop/VNC instances.
- **Confidence Level:** Moderate.

## 5. Vulnerability and Signature Summary
- **Primary Alert Signatures:**
    - GPL INFO VNC server response (High frequency)
    - SURICATA SSH invalid banner
    - SMB Negotiation (Port 445)
- **CVE Activity:** Indicators of `CVE-2023-46604` (Apache ActiveMQ RCE) were observed within the broader dataset, though frequency remains low compared to mass scanning.

## 6. Investigative Conclusion
The investigation confirms that while the majority of honeypot traffic is composed of automated SMB scanning from South American infrastructure, a significant and highly targeted threat exists from Romanian-based actor **80.94.92.182**. This actor is specifically pursuing blockchain (Solana) infrastructure through targeted SSH credential spraying.

### Recommendations
1. **Immediate Blocking:** Blacklist IP `80.94.92.182` across all perimeter defenses.
2. **Blockchain Hardening:** Organizations running Solana nodes should disable SSH password authentication and enforce strict SSH key-based access.
3. **SMB Exposure:** Ensure port 445 is not exposed to the public internet, particularly to the observed South American IP ranges.
