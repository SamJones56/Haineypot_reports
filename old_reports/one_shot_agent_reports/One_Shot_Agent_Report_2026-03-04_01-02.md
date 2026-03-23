# Investigation Report: 2026-03-04T01:00:04Z to 2026-03-04T02:00:04Z

## Investigation Scope
- investigation_start: 2026-03-04T01:00:04Z
- investigation_end: 2026-03-04T02:00:04Z
- completion_status: Complete
- degraded_mode: false

## Executive Triage Summary
- **Top services/ports of interest:** VNC (ports 5900, 5902, 5903, 5906, 5907, 5911, 5912, 5915, 5925, 5926), SSH (port 22), SMTP (port 25), Postgres (port 5434).
- **Top confirmed known exploitation:** Extensive VNC exploitation attempts, primarily targeting CVE-2006-2369 ("VNC Server Not Requiring Authentication").
- **Top unmapped exploit-like items:** None identified as truly unmapped exploit-like, as VNC activity is well-mapped to a known CVE.
- **Botnet/campaign mapping highlights:** High volume VNC scanning activity originating from various ASNs, most notably Dynu Systems Incorporated and DigitalOcean, LLC, largely from the United States, indicating widespread opportunistic scanning. Credential stuffing attempts observed across various honeypots. Industrial Control System (ICS) protocol scanning (Kamstrup) targeting Conpot honeypots.
- **Major uncertainties if degraded:** None.

## Candidate Discovery Summary
- **Total attack events:** 4814
- **Top attacking countries:** United States (3371), Ukraine (232), Australia (201), Romania (159), Switzerland (153)
- **Top attacking source IPs:** 207.174.0.19 (1570), 136.114.97.84 (330), 129.212.179.18 (262), 129.212.188.196 (262), 77.83.39.212 (228)
- **Top CVEs:** CVE-2006-2369 (1580), CVE-2024-14007 CVE-2024-14007 (3), CVE-2002-1149 (1)
- **Top alert categories:** Misc activity (7417), Attempted Administrator Privilege Gain (1583), Generic Protocol Command Decode (808)
- **Honeypot activity:** Tanner honeypot observed requests for web paths like `/`, `/admin/config.php`, `/r0r.php`. Conpot honeypot observed Kamstrup protocol interactions. Redis honeypot observed connection attempts and `info`/`PING`/`QUIT` commands. Adbhoney honeypot had no activity.
- **Missing inputs/errors:** The `url_path` field was not present in the general field presence check, but `tanner_unifrom_resource_search` successfully identified paths using its specific field.

## Emerging n-day Exploitation
- **CVE-2006-2369 - VNC Server Not Requiring Authentication**
    - **cve/signature mapping:** CVE-2006-2369, ET INFO VNC Authentication Failure (2002920), ET EXPLOIT VNC Server Not Requiring Authentication (case 2) (2002923)
    - **evidence summary:** 1580 CVE events, 1580 "VNC Authentication Failure" signature events, 1580 "VNC Server Not Requiring Authentication" signature events.
    - **affected service/port:** VNC (TCP ports 5900, 5902, 5903, 5906, 5907, 5911, 5912, 5915, 5925, 5926)
    - **confidence:** High
    - **operational notes:** Widespread scanning for unauthenticated VNC services. Monitor VNC ports and ensure proper authentication.

## Novel or Zero-Day Exploit Candidates
- None identified. All significant exploit-like behavior is mapped to known CVEs or commodity activity.

## Botnet/Campaign Infrastructure Mapping
- **Opportunistic VNC Scanning Campaign**
    - **item_id:** N/A (broad campaign)
    - **campaign_shape:** Spray (widespread scanning across many targets)
    - **suspected_compromised_src_ips:** 207.174.0.19 (1570), 136.114.97.84 (330), 129.212.179.18 (262), 129.212.188.196 (262), 77.83.39.212 (228)
    - **ASNs / geo hints:** Dynu Systems Incorporated (ASN 398019, US), DigitalOcean, LLC (ASN 14061, US), Google LLC (ASN 396982), Kprohost LLC (ASN 214940, Ukraine), Private Layer INC (ASN 51852)
    - **suspected_staging indicators:** None explicitly identified, likely direct exploitation.
    - **suspected_c2 indicators:** None explicitly identified.
    - **confidence:** High
    - **operational notes:** Block known attacker IPs and monitor VNC services for unauthorized access attempts. Investigate the large volume of traffic from Dynu Systems Incorporated and DigitalOcean.

- **Credential Stuffing/Brute Force Campaign**
    - **item_id:** N/A (broad campaign)
    - **campaign_shape:** Spray
    - **suspected_compromised_src_ips:** IPs associated with various honeypot interactions (not individually tracked for this item).
    - **ASNs / geo hints:** Various.
    - **suspected_staging indicators:** None explicitly identified.
    - **suspected_c2 indicators:** None explicitly identified.
    - **confidence:** Medium
    - **operational notes:** Monitor for common username/password combinations across services. Implement strong password policies and multi-factor authentication.

## Odd-Service / Minutia Attacks
- **Kamstrup Protocol Scanning on Conpot**
    - **service_fingerprint:** Conpot Honeypot, Kamstrup protocol (port and exact protocol details not fully specified in tool output, but indicates ICS protocol activity).
    - **why it’s unusual/interesting:** Kamstrup protocol is associated with smart metering and utility infrastructure, indicating scanning interest in Industrial Control Systems (ICS).
    - **evidence summary:** 3 `kamstrup_protocol` events, 2 `kamstrup_management_protocol` events. Input `b'0018080404030807080508060401050106010503060302010203ff0100010000120000002b0009080304030303020301003300260024001d0020534cf0b7b374105d445668ce6dbc7355403edcc1561bf02835b40f942e'` observed.
    - **confidence:** High
    - **recommended monitoring pivots:** Further analyze source IPs targeting Conpot, especially for specific Kamstrup-related commands or unusual packet sizes/sequences.

## Known-Exploit / Commodity Exclusions
- **Brute Force/Credential Noise:**
    - **Evidence:** "admin", "user", "root", "solana" usernames and "solana", "123456" passwords seen across various honeypots.
- **Common Scanners:**
    - **Evidence:** "ET SCAN MS Terminal Server Traffic on Non-standard Port" (250 counts), general background noise and scanning attempts across various ports.
- **Known Commodity Bot Patterns:**
    - **Evidence:** "ET DROP Dshield Block Listed Source group 1" (156 counts), indicating activity from known malicious IPs.
- **VNC Exploitation:**
    - **Evidence:** High volume of VNC-related alerts and CVE-2006-2369 exploitation attempts, consistent with opportunistic scanning for unauthenticated VNC servers.

## Infrastructure & Behavioral Classification
- **VNC Exploitation (CVE-2006-2369):** Exploitation, Spray campaign shape, high infrastructure reuse (same IPs targeting multiple VNC ports).
- **Credential Stuffing:** Scanning/Exploitation attempts, Spray campaign shape, likely various infra reuse.
- **Kamstrup Protocol Scanning:** Scanning, Unknown campaign shape, potential focused reconnaissance on ICS.
- **General Scanning:** Scanning, Spray campaign shape.

## Evidence Appendix
- **CVE-2006-2369 - VNC Server Not Requiring Authentication**
    - **source IPs with counts:** 207.174.0.19 (1570), 129.212.179.18 (262), 129.212.188.196 (262), 113.161.121.229 (57), 165.245.138.210 (57)
    - **ASNs with counts:** Dynu Systems Incorporated (ASN 398019, 1570), DigitalOcean, LLC (ASN 14061, 1153), Google LLC (ASN 396982, 558)
    - **target ports/services:** VNC (TCP 5900, 5902, 5903, 5906, 5907, 5911, 5912, 5915, 5925, 5926)
    - **paths/endpoints:** Not directly applicable for VNC
    - **payload/artifact excerpts:** "VNC Authentication Failure", "VNC Server Not Requiring Authentication (case 2)"
    - **staging indicators:** missing
    - **temporal checks results:** unavailable

- **Kamstrup Protocol Scanning on Conpot**
    - **source IPs with counts:** Not directly available from tool output, but associated with Conpot honeypot activity.
    - **ASNs with counts:** Not directly available.
    - **target ports/services:** Conpot honeypot, Kamstrup protocol
    - **paths/endpoints:** Input `b'0018080404030807080508060401050106010503060302010203ff0100010000120000002b0009080304030303020301003300260024001d0020534cf0b7b374105d445668ce6dbc7355403edcc1561bf02835b40f942e'`
    - **payload/artifact excerpts:** `kamstrup_protocol`, `kamstrup_management_protocol`
    - **staging indicators:** missing
    - **temporal checks results:** unavailable

## Indicators of Interest
- **IPs**: 207.174.0.19, 136.114.97.84, 129.212.179.18, 129.212.188.196, 77.83.39.212 (top attackers for VNC/general scanning)
- **CVEs**: CVE-2006-2369
- **Signatures**: GPL INFO VNC server response (2100560), ET INFO VNC Authentication Failure (2002920), ET EXPLOIT VNC Server Not Requiring Authentication (case 2) (2002923)
- **Usernames**: admin, user, root, solana
- **Passwords**: solana, 123456
- **Paths**: /admin/config.php, /r0r.php, /recordings/misc/graph.php (Tanner honeypot)

## Backend Tool Issues
- None. All requested tools returned valid responses.
