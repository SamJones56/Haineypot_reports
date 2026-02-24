# Cyber Threat Investigation Report - Last 30 Minutes

## 1. Investigation Scope
- **Investigation Start (UTC):** 2026-02-24T15:00:00Z
- **Investigation End (UTC):** 2026-02-24T15:30:00Z
- **Focus:** Quantification of honeypot telemetry and correlation of significant attack patterns.

## 2. Baseline Metrics (Quantified)
- **Total Attack Volume:** 2,591 events.
- **Top Source IPs:**
  1. 134.199.173.225 (1,074 counts) - Australia (DigitalOcean)
  2. 159.65.85.38 (300 counts) - United States (DigitalOcean)
  3. 200.105.151.2 (278 counts) - Bolivia (AXS Bolivia S. A.)
  4. 157.245.110.216 (110 counts) - India (DigitalOcean)
  *Note: IP 103.158.121.141 (Indonesia) recorded 1,646 events, primarily appearing as Suricata alerts.*
- **Top ASNs:**
  - AS14061 DigitalOcean, LLC (1,666 counts, ~64%)
  - AS26210 AXS Bolivia S. A. (278 counts, ~10.7%)
- **Top Countries:** Australia (1,074), United States (518), United Kingdom (318).
- **Top Services/Ports:**
  - Port 445 (SMB): Significant activity from Bolivia and Indonesia.
  - Port 22 (SSH): Primary focus for Australian and UK-based traffic.
  - VNC (5901-5905): Notable concentration from US-based IPs.
- **Top Alert Signatures:**
  - ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (1,640 counts)
  - SURICATA IPv4/AF-PACKET truncated packet (316 combined)
  - GPL INFO VNC server response (112 counts)
- **Credential Patterns:**
  - Usernames: root (47), guest (34), user (23).
  - Passwords: 123456 (57), 123 (8), password (6).

## 3. Temporal Comparison
- **Current Window (15:00-15:30):** 2,591 attacks.
- **Previous Window (14:30-15:00):** 3,402 attacks.
- **Trend:** Decrease of ~24% in total volume, but a sharp behavioral pivot. The previous window was dominated by Brazilian VNC scanning (IP 189.87.56.210), whereas the current window is defined by Indonesian SMB exploitation attempts and Australian SSH brute-forcing. DoublePulsar alerts surged from 18 to 1,640.

## 4. Significant Findings
### High-Volume SMB DoublePulsar Campaign
- **Source IP:** 103.158.121.141 (PT Anugerah Cimanuk Raya, Indonesia).
- **Activity:** Generated 1,640 alerts for DoublePulsar backdoor communication over port 445.
- **Details:** The activity is part of a persistent flow (ID 485709357652451) that escalated dramatically in the current window (from 62 to 1,646 events). This indicates an active attempt to establish or utilize a backdoor, likely following an MS17-010 (EternalBlue) exploit attempt.

### Go-based SSH Brute Force
- **Source IP:** 134.199.173.225 (DigitalOcean, Australia).
- **Target:** Port 22.
- **Tooling:** Identified as `SSH-2.0-Go`.
- **Behavior:** Rapid credential testing using common pairs such as `hive/hive` and `root/123456`.

## 5. Infrastructure & Behavioral Classification
- **CVE-Specific Exploitation Campaign (DoublePulsar/SMB):**
  - **Evidence:** 1,640 counts of signature 2024766 (DoublePulsar) from 103.158.121.141.
  - **Confidence:** High.
- **Automated Opportunistic Scanning (SSH Brute Force):**
  - **Evidence:** 1,074 events from 134.199.173.225 using Go-based SSH client and standard wordlists.
  - **Confidence:** High.

## 6. Analytical Assessment
The environment is currently experiencing a targeted surge in SMB-related exploitation attempts originating from Indonesia. While the overall attack volume decreased, the severity increased due to the prevalence of post-exploitation backdoor signatures (DoublePulsar). Simultaneously, a Go-based scanner from DigitalOcean (Australia) is aggressively probing SSH. The shift away from Brazilian-led VNC scanning suggests the conclusion of one automated cycle and the start of another.

## 7. Confidence Breakdown
- **SMB Exploitation (103.158.121.141):** High. Metrics show a clear correlation between the IP and the specific DoublePulsar signature.
- **SSH Scanning (134.199.173.225):** High. Cowrie logs explicitly detail the SSH handshake and failed login attempts.
- **Bolivian SMB Probing:** Moderate. Lower volume compared to the Indonesian source.

## 8. Indicators of Interest
| Type | Value | Organization | Country |
| :--- | :--- | :--- | :--- |
| IP | 103.158.121.141 | PT Anugerah Cimanuk Raya | Indonesia |
| IP | 134.199.173.225 | DigitalOcean, LLC | Australia |
| IP | 200.105.151.2 | AXS Bolivia S. A. | Bolivia |
| CVE | DoublePulsar (MS17-010) | N/A | N/A |
| User Agent | SSH-2.0-Go | N/A | N/A |
