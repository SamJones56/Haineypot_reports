# Investigation Report

## 1) Investigation Scope
- investigation_start: 2026-03-08T18:00:07Z
- investigation_end: 2026-03-08T21:00:07Z
- completion_status: Complete
- degraded_mode: false

## 2) Executive Triage Summary
- Total attacks observed: 16758.
- Top attacking countries are United States, India, and Romania.
- Significant VNC exploitation attempts, primarily targeting authentication bypass (CVE-2006-2369).
- High volume of "known attacker" IPs, with DigitalOcean and INSPIREIT NETWORK SOLUTIONS PRIVATE LIMITED being prominent ASNs.
- Detected credential stuffing/brute-force activity using common usernames (root, admin) and passwords (123456, password).
- Unusual RDP traffic observed on non-standard ports.
- Web reconnaissance for sensitive configuration files (`/.env`) and Android Debug Bridge (ADB) command execution attempts.
- No novel or zero-day exploits were identified.

## 3) Candidate Discovery Summary
- Total attack events: 16758
- Top 5 countries: United States (5381), India (3114), Romania (972), Ukraine (695), Australia (675).
- Top 10 source IPs: 103.75.60.46 (1889), 136.114.97.84 (936), 46.19.137.194 (453), 134.209.37.134 (451), 129.212.184.194 (340), 14.96.246.174 (337), 139.59.23.169 (330), 170.64.152.136 (314), 165.245.138.210 (313), 162.243.232.129 (304).
- Top 10 ASNs: DigitalOcean, LLC (3962), INSPIREIT NETWORK SOLUTIONS PRIVATE LIMITED (1889), Google LLC (1351), Unmanaged Ltd (956), FOP Dmytro Nedilskyi (668), Private Layer INC (453), IP Volume inc (444), Akamai Connected Cloud (407), Tata Teleservices ISP AS (337), UCLOUD INFORMATION TECHNOLOGY HK LIMITED (316).
- Top 5 Alert Categories: Misc activity (24383), Generic Protocol Command Decode (3911), Attempted Administrator Privilege Gain (1911), Attempted Information Leak (973), Misc Attack (848).
- Top 5 CVEs: CVE-2006-2369 (1834), CVE-2025-55182 CVE-2025-55182 (117), CVE-2024-38816 CVE-2024-38816 (10), CVE-2024-14007 CVE-2024-14007 (7), CVE-2021-3449 CVE-2021-3449 (6).
- Top 5 Alert Signatures: GPL INFO VNC server response (21921), ET EXPLOIT VNC Server Not Requiring Authentication (case 2) (1834), ET INFO VNC Authentication Failure (1833), SURICATA STREAM 3way handshake SYN resend different seq on SYN recv (1126), ET SCAN MS Terminal Server Traffic on Non-standard Port (790).
- Top 3 IP reputations: known attacker (8096), mass scanner (245), tor exit node (6).
- Top 5 P0f OS Distributions: Windows NT kernel (50284), Linux 2.2.x-3.x (27265), Windows NT kernel 5.x (23477), Linux 3.11 and newer (3154), Windows 7 or 8 (3612).
- Honeypot data: Adbhoney captured `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"` input (2 counts). Tanner honeypot observed requests to `/` (46 counts), `/.env` (3 counts), `/boaform/admin/formLogin?username=user&psd=user` (1 count). Redis honeypot actions include `Closed` (7 counts), `NewConnect` (7 counts), `info` (4 counts). No Conpot input or protocol data found. No Adbhoney malware samples.
- Common usernames: root (216), admin (63), 345gs5662d34 (45), user (44), ubuntu (40).
- Common passwords: 345gs5662d34 (45), 123456 (44), 3245gs5662d34 (43), 12345678 (38), password (38).
- Field presence check indicates `alert.cve.id`, `alert.signature`, `http.url`, and `src_ip` fields are present, but `url.path` is not.

## 4) Emerging n-day Exploitation
- **CVE-2006-2369: VNC Server Authentication Bypass**
    - cve/signature mapping: CVE-2006-2369, ET EXPLOIT VNC Server Not Requiring Authentication (case 2), ET INFO VNC Authentication Failure
    - evidence summary: 1834 counts of CVE-2006-2369 alerts, 1834 counts for signature ID 2002923, 1833 counts for signature ID 2002920.
    - affected service/port: VNC (ports 5901-5913, specifically observed in traffic originating from Australia and the United States).
    - confidence: High
    - operational notes: Continued attempts to exploit VNC servers lacking proper authentication. Review VNC configurations and enforce strong authentication.

- **CVE-2025-55182: Unspecified Vulnerability**
    - cve/signature mapping: CVE-2025-55182 CVE-2025-55182
    - evidence summary: 117 counts of CVE-2025-55182 alerts.
    - affected service/port: Not explicitly identified, but associated with "Misc activity" alert category.
    - confidence: Medium (further investigation needed to determine specific impact and affected services)
    - operational notes: Monitor for additional context or related activity for this CVE.

## 5) Novel or Zero-Day Exploit Candidates
None identified.

## 6) Botnet/Campaign Infrastructure Mapping
- **Campaign targeting VNC services (via CVE-2006-2369)**
    - item_id: VNC-Exploit-Campaign-20260308
    - campaign_shape: Spray (distributed scanning and exploitation attempts against VNC services).
    - suspected_compromised_src_ips: Top IPs include 103.75.60.46, 136.114.97.84, 46.19.137.194, 134.209.37.134, 129.212.184.194.
    - ASNs / geo hints: Primarily India (INSPIREIT NETWORK SOLUTIONS PRIVATE LIMITED), United States (DigitalOcean, LLC, Google LLC), Romania (Private Layer INC).
    - suspected_staging indicators: None identified.
    - suspected_c2 indicators: None identified.
    - confidence: High
    - operational notes: Prioritize patching of VNC vulnerabilities and restrict VNC access from external networks. Block identified malicious source IPs.

- **Credential Stuffing/Brute Force Campaign**
    - item_id: Credential-Stuffing-20260308
    - campaign_shape: Spray (widespread attempts with common credentials).
    - suspected_compromised_src_ips: Various IPs with "known attacker" reputation.
    - ASNs / geo hints: Broadly distributed globally, with DigitalOcean, LLC and Google LLC ASNs frequently observed.
    - suspected_staging indicators: None identified.
    - suspected_c2 indicators: None identified.
    - confidence: High
    - operational notes: Enforce strong, unique passwords and multi-factor authentication (MFA) for all services. Implement rate limiting and account lockout policies.

## 7) Odd-Service / Minutia Attacks
- **MS Terminal Server Traffic on Non-standard Port**
    - service_fingerprint: RDP (port 3389) on non-standard ports.
    - why it’s unusual/interesting: RDP traffic on unexpected ports often indicates attempts to bypass security controls or obscure malicious activity.
    - evidence summary: 790 counts of "ET SCAN MS Terminal Server Traffic on Non-standard Port" alerts (signature ID 2023753).
    - confidence: High
    - recommended monitoring pivots: Audit RDP server configurations, ensure RDP is not exposed directly to the internet, and monitor for RDP connections on unusual ports.

- **Adbhoney Command Execution Attempt**
    - service_fingerprint: Adbhoney honeypot (Android Debug Bridge).
    - why it’s unusual/interesting: The command `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"` suggests reconnaissance to gather system information (device name, user).
    - evidence summary: 2 counts of this specific command input in Adbhoney.
    - confidence: Medium
    - recommended monitoring pivots: Monitor for further ADB-related command execution attempts and ensure ADB is properly secured or disabled when not in use.

- **Tanner Honeypot Web Requests for `/.env`**
    - service_fingerprint: HTTP/S (web services).
    - why it’s unusual/interesting: Requests for `.env` files are common reconnaissance attempts by attackers to find environment variables and sensitive configuration data.
    - evidence summary: 3 counts of requests to `/.env` observed by Tanner honeypot.
    - confidence: High
    - recommended monitoring pivots: Ensure `.env` files and other sensitive configuration files are not publicly accessible on web servers. Implement robust web application firewalls (WAFs) and monitor web server logs for similar reconnaissance attempts.

## 8) Known-Exploit / Commodity Exclusions
- **Brute Force/Credential Noise:** Evident from high counts of common usernames (e.g., "root", "admin", "user") and passwords (e.g., "123456", "password") across various honeypots. This is a common and pervasive attack type.
- **Generic Network Scanning:** "SURICATA STREAM 3way handshake SYN resend different seq on SYN resend" and "SURICATA STREAM ESTABLISHED SYN resend with different seq" alerts indicate routine network scanning activity.
- **VNC Reconnaissance:** The "GPL INFO VNC server response" signature, with over 21,000 counts, represents widespread scanning to identify VNC services, often a precursor to exploitation attempts.
- **Miscellaneous Activity:** The "Misc activity" alert category accounts for a large volume of events, likely encompassing various low-signal and commodity attack patterns.

## 9) Infrastructure & Behavioral Classification
- **Exploitation:**
    - VNC: Attempts to exploit known authentication bypass vulnerabilities.
    - RDP: Targeted access attempts on non-standard ports.
    - Adbhoney: Command injection for system information gathering.
- **Scanning:**
    - Network: Extensive SYN resend activity and probing for open ports.
    - RDP: Identification of RDP services, potentially on unusual ports.
    - Web: Discovery of sensitive configuration files (`/.env`).
- **Campaign Shape:** Predominantly "Spray" campaigns, characterized by broad, untargeted attacks from various source IPs against multiple services.
- **Infra Reuse Indicators:** Significant use of cloud provider ASNs (DigitalOcean, LLC, Google LLC, INSPIREIT NETWORK SOLUTIONS PRIVATE LIMITED) by attackers, along with a high prevalence of "known attacker" IP reputations.
- **Odd-Service Fingerprints:** VNC on various ports (5901-5913), RDP on non-standard ports, Adbhoney, and Redis honeypot activity.

## 10) Evidence Appendix

- **CVE-2006-2369: VNC Server Authentication Bypass**
    - Source IPs with counts: 103.75.60.46 (1889), 136.114.97.84 (936), 46.19.137.194 (453), 134.209.37.134 (451), 129.212.184.194 (340).
    - ASNs with counts: DigitalOcean, LLC (3962), INSPIREIT NETWORK SOLUTIONS PRIVATE LIMITED (1889), Private Layer INC (453), Google LLC (1351).
    - Target ports/services: VNC (5901, 5902, 5903, 5904, 5906, 5907, 5911, 5912, 5913).
    - Paths/endpoints: Not explicitly available for VNC.
    - Payload/artifact excerpts: Implied by Suricata signatures: "ET EXPLOIT VNC Server Not Requiring Authentication (case 2)" and "ET INFO VNC Authentication Failure".
    - Staging indicators: Missing.
    - Temporal checks results: Unavailable.

- **Credential Stuffing/Brute Force Campaign**
    - Source IPs with counts: Broadly distributed among top attacker IPs.
    - ASNs with counts: Broadly distributed among top attacker ASNs.
    - Target ports/services: Services susceptible to credential attacks (e.g., SSH on port 22, web login portals).
    - Paths/endpoints: `/boaform/admin/formLogin?username=user&psd=user` (Tanner).
    - Payload/artifact excerpts: Usernames: "root", "admin", "345gs5662d34", "user", "ubuntu". Passwords: "345gs5662d34", "123456", "3245gs5662d34", "12345678", "password".
    - Staging indicators: Missing.
    - Temporal checks results: Unavailable.

- **MS Terminal Server Traffic on Non-standard Port**
    - Source IPs with counts: Various, implicit from detection of 790 events.
    - ASNs with counts: Various, implicit from detection of 790 events.
    - Target ports/services: RDP (default 3389) on non-standard ports.
    - Paths/endpoints: Not applicable.
    - Payload/artifact excerpts: Implied by Suricata signature "ET SCAN MS Terminal Server Traffic on Non-standard Port".
    - Staging indicators: Missing.
    - Temporal checks results: Unavailable.

## 11) Indicators of Interest
- **Source IPs (Top Attackers):**
    - 103.75.60.46
    - 136.114.97.84
    - 46.19.137.194
    - 134.209.37.134
    - 129.212.184.194
- **CVEs:**
    - CVE-2006-2369
    - CVE-2025-55182
- **Suricata Signatures:**
    - GPL INFO VNC server response (2100560)
    - ET EXPLOIT VNC Server Not Requiring Authentication (case 2) (2002923)
    - ET INFO VNC Authentication Failure (2002920)
    - ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753)
- **Honeypot Artifacts:**
    - Adbhoney input: `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`
    - Tanner paths: `/.env`, `/boaform/admin/formLogin?username=user&psd=user`
- **Common Usernames (attempted):**
    - root
    - admin
    - 345gs5662d34
    - user
- **Common Passwords (attempted):**
    - 345gs5662d34
    - 123456
    - password

## 12) Backend Tool Issues
- The `url.path` field was not present according to `field_presence_check`. This may have limited comprehensive analysis of web application path-based attacks beyond what `tanner_unifrom_resource_search` explicitly returned.
