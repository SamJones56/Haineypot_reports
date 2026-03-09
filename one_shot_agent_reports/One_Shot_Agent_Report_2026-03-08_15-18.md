# Investigation Report 2026-03-08T15:00:08Z to 2026-03-08T18:00:08Z

## Investigation Scope
- investigation_start: 2026-03-08T15:00:08Z
- investigation_end: 2026-03-08T18:00:08Z
- completion_status: Complete
- degraded_mode: false

## Executive Triage Summary
- Top services/ports of interest include VNC (ports 5901-5913), SMB (port 445), SSH (port 22), and various web/management ports (8009, 10000, 8083, 8089, 8088).
- Significant known exploitation observed for CVE-2006-2369 (VNC server not requiring authentication).
- No clear unmapped exploit-like items were identified.
- Botnet/campaign mapping indicates activity from DigitalOcean and National Internet Backbone ASNs, primarily targeting VNC and SMB services.
- Notable activity on ADBhoneypot with attempts to execute commands.
- Common usernames like "root", "admin", "user" and passwords like "345gs5662d34", "12345678", "password" suggest credential stuffing attempts.

## Candidate Discovery Summary
- Total attacks observed: 18100
- Top countries: United States, India, South Korea, Hong Kong, Australia
- Top source IPs: 61.1.174.138, 136.114.97.84, 134.209.37.134, 129.212.184.194, 139.59.45.43
- Top ASNs: DigitalOcean, LLC (ASN 14061), National Internet Backbone (ASN 9829), Google LLC (ASN 396982), Korea Telecom (ASN 4766), FOP Dmytro Nedilskyi (ASN 211736)
- Suricata Alerts: Predominantly VNC-related and generic protocol command decode.
- CVEs: CVE-2006-2369, CVE-2025-55182, CVE-2024-14007, CVE-2021-3449, CVE-2002-0013, CVE-2002-0012.
- Honeypot activity: Credential stuffing attempts on various honeypots, with ADBhoneypot showing command execution attempts and Tanner honeypot detecting requests for common sensitive files. No Conpot or Adbhoney malware samples were found.

## Emerging n-day Exploitation
- **cve/signature mapping:** CVE-2006-2369, "ET EXPLOIT VNC Server Not Requiring Authentication (case 2)" (signature ID 2002923)
- **evidence summary:** 972 events related to CVE-2006-2369, targeting various VNC ports.
- **affected service/port:** VNC (various ports like 5901-5913)
- **confidence:** High
- **operational notes:** Continued monitoring for VNC exploitation, especially from IPs associated with these alerts.

## Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
- No strong candidates identified.

## Botnet/Campaign Infrastructure Mapping
- **item_id:** 1
- **campaign_shape:** Spray (wide range of IPs and ports targeted)
- **suspected_compromised_src_ips:**
    - 61.1.174.138 (3107 counts)
    - 136.114.97.84 (788 counts)
    - 134.209.37.134 (450 counts)
    - 129.212.184.194 (338 counts)
    - 139.59.45.43 (333 counts)
- **ASNs / geo hints:** DigitalOcean, LLC (US), National Internet Backbone (KR), Google LLC (US), Korea Telecom (KR), FOP Dmytro Nedilskyi (UA). United States and India are top attacking countries.
- **suspected_staging indicators:** No direct staging indicators identified.
- **suspected_c2 indicators:** No direct C2 indicators identified.
- **confidence:** Medium (based on high volume from specific ASNs and targeting patterns)
- **operational notes:** Monitor IPs from DigitalOcean and National Internet Backbone ASNs for continued VNC and SMB scanning/exploitation attempts.

## Odd-Service / Minutia Attacks
- **service_fingerprint:** VNC (ports 5901-5913)
- **why it’s unusual/interesting:** Repeated attempts to access VNC without authentication (CVE-2006-2369) and general VNC server responses, suggesting broad scanning for vulnerable VNC services.
- **evidence summary:** 20284 events for "GPL INFO VNC server response", 972 for "ET EXPLOIT VNC Server Not Requiring Authentication".
- **confidence:** High
- **recommended monitoring pivots:** Monitor for VNC traffic on non-standard ports and unauthenticated access attempts.

- **service_fingerprint:** ADBhoneypot (various ports, typically 5555)
- **why it’s unusual/interesting:** Attempts to execute commands like "echo \"$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)\"" on ADBhoneypot, indicating reconnaissance or initial compromise attempts.
- **evidence summary:** 1 event for specific command execution.
- **confidence:** Medium
- **recommended monitoring pivots:** Monitor for suspicious command execution attempts on ADB services.

- **service_fingerprint:** HTTP (Tanner Honeypot, various web ports)
- **why it’s unusual/interesting:** Requests for sensitive files like "/.env", "/phpinfo.php", "/.aws/credentials", and "/.env.bak" indicating attempts to discover configuration files or sensitive information.
- **evidence summary:** 54 requests for "/", 3 for "/.env", 2 for "/phpinfo.php", 1 for "/.aws/credentials", 1 for "/.env.bak".
- **confidence:** Medium
- **recommended monitoring pivots:** Monitor web server logs for requests to common sensitive file paths.

## Known-Exploit / Commodity Exclusions
- **Credential Noise:** Numerous attempts with common usernames ("root", "admin") and passwords ("123456", "password", "345gs5662d34") across various honeypots.
- **Scanning:** Broad scanning for VNC services, SMB (port 445), and SSH (port 22) as evidenced by high alert counts and port activity.
- **Known Bot Patterns:** The source IP reputation data shows "known attacker" and "mass scanner" labels, indicating activity from established malicious infrastructure.

## Infrastructure & Behavioral Classification
- **Exploitation vs Scanning:** A mix of both; high volume scanning for common services (VNC, SMB, SSH) combined with specific exploitation attempts against VNC (CVE-2006-2369) and credential stuffing.
- **Campaign Shape:** Appears to be broad spray-and-pray scanning with targeted credential brute-forcing.
- **Infra Reuse Indicators:** High attack counts from IPs hosted in major cloud providers (DigitalOcean, Google Cloud) and known national internet backbones, suggesting re-purposed infrastructure.
- **Odd-Service Fingerprints:** VNC exploitation attempts, ADB command execution attempts, and sensitive file requests on web services.

## Evidence Appendix
- ### Emerging n-day Exploitation (CVE-2006-2369)
    - **source IPs with counts:** 61.1.174.138 (many related VNC events), specific IPs associated with the 972 CVE-2006-2369 alerts would need further drill-down.
    - **ASNs with counts:** DigitalOcean, LLC (ASN 14061), National Internet Backbone (ASN 9829), etc.
    - **target ports/services:** VNC (5901-5913)
    - **paths/endpoints:** Not directly applicable for VNC exploitation in this context, but implies VNC service open.
    - **payload/artifact excerpts:** "ET EXPLOIT VNC Server Not Requiring Authentication (case 2)"
    - **staging indicators:** unavailable
    - **temporal checks results:** Events observed throughout the investigation window.

- ### Botnet/Campaign Infrastructure Mapping (Item 1)
    - **source IPs with counts:** 61.1.174.138 (3107), 136.114.97.84 (788), 134.209.37.134 (450), 129.212.184.194 (338), 139.59.45.43 (333)
    - **ASNs with counts:** DigitalOcean, LLC (4344), National Internet Backbone (3109), Google LLC (1170)
    - **target ports/services:** VNC (5901-5913), SMB (445), SSH (22), others.
    - **paths/endpoints:**
        - ADBhoneypot: "echo \"$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)\""
        - Tanner: "/", "/.env", "/phpinfo.php", "/.aws/credentials", "/.env.bak"
    - **payload/artifact excerpts:** "GPL INFO VNC server response", "ET EXPLOIT VNC Server Not Requiring Authentication (case 2)", common usernames/passwords.
    - **staging indicators:** unavailable
    - **temporal checks results:** Events observed throughout the investigation window.

## Indicators of Interest
- **IPs:** 61.1.174.138, 136.114.97.84, 134.209.37.134, 129.212.184.194, 139.59.45.43
- **CVEs:** CVE-2006-2369
- **Suricata Signature IDs:** 2100560, 2002923, 2002920
- **Ports:** 5901-5913 (VNC), 445 (SMB), 22 (SSH)
- **Paths:** /, /.env, /phpinfo.php, /.aws/credentials, /.env.bak
- **Usernames:** root, admin, user, 345gs5662d34
- **Passwords:** 345gs5662d34, 12345678, password

## Backend Tool Issues
- None. All requested tool calls completed successfully.