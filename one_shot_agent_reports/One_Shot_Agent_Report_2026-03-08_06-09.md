# Investigation Report

## 1) Investigation Scope
- investigation_start: 2026-03-08T06:00:04Z
- investigation_end: 2026-03-08T09:00:04Z
- completion_status: Complete
- degraded_mode: false

## 2) Executive Triage Summary
- Top services/ports of interest include VNC (port 590X), SMB (port 445), SSH (port 22), and HTTP (port 80).
- Emerging n-day exploitation observed for CVE-2025-55182 and CVE-2019-11500.
- Significant "Misc activity" and "Generic Protocol Command Decode" detected by Suricata.
- Honeypots show common credential stuffing attempts against "root" and "admin" usernames.
- A notable portion of attacking IPs are categorized as "known attacker".

## 3) Candidate Discovery Summary
- Total attacks observed: 17623.
- Top attacking countries are United States, Indonesia, Türkiye, India, and United Kingdom.
- No Adbhoney malware samples or Conpot input/protocol data were observed.
- The `url.path` field was not present in the field presence check.

## 4) Emerging n-day Exploitation
- **cve/signature mapping:** CVE-2025-55182 (90 counts) and CVE-2019-11500 (11 counts). Signatures like "GPL INFO VNC server response" (28877 counts) and "ET SCAN MS Terminal Server Traffic on Non-standard Port" (643 counts) are prominent.
- **evidence summary:**
    - CVE-2025-55182: 90 occurrences.
    - CVE-2019-11500: 11 occurrences.
    - Top Suricata signatures include "GPL INFO VNC server response", "SURICATA IPv4 truncated packet", and "SURICATA AF-PACKET truncated packet".
- **affected service/port:** VNC (ports 5902, 5903, 5904), SMB (port 445), SSH (port 22), HTTP (port 80, 3128, 8728).
- **confidence:** High
- **operational notes:** Monitor for increased activity related to these CVEs and associated signatures.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
- None identified in this reporting window.

## 6) Botnet/Campaign Infrastructure Mapping
- **item_id:** N/A
- **campaign_shape:** Predominantly spray (credential stuffing, mass scanning), with some focused activity on specific ports.
- **suspected_compromised_src_ips:**
    - 45.95.214.24 (945 counts)
    - 136.114.97.84 (740 counts)
    - 46.19.137.194 (561 counts)
- **ASNs / geo hints:**
    - DigitalOcean, LLC (ASN 14061, 4105 counts)
    - Google LLC (ASN 396982, 1433 counts)
    - Emre Anil Arslan (ASN 216099, 945 counts)
- **suspected_staging indicators:** Tanner honeypot observed requests for "/.env", "/.well-known/security.txt", and "/api/graphql", which can indicate reconnaissance for sensitive files or API endpoints.
- **suspected_c2 indicators:** No direct C2 indicators were definitively identified, however the presence of "known attacker" IPs suggests potential involvement in broader campaigns.
- **confidence:** Medium
- **operational notes:** Block highly active IPs, investigate IP ranges belonging to suspicious ASNs for further activity, monitor for newly observed paths.

## 7) Odd-Service / Minutia Attacks
- **service_fingerprint:** VNC (ports 5902, 5903, 5904) with high activity from the United States.
- **why it’s unusual/interesting:** VNC is often used for remote desktop control, and persistent scanning or connection attempts could indicate targeted attacks or attempts to gain unauthorized access to graphical interfaces. The high volume specifically targeting these ports from the US is notable.
- **evidence summary:** United States: 448 counts on port 5902, 284 counts on port 5903, 273 counts on port 5904. The signature "GPL INFO VNC server response" has 28877 counts.
- **confidence:** High
- **recommended monitoring pivots:** Monitor VNC service logs, look for unusual VNC connection attempts, and correlate with failed login attempts.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise:** High volume of attempts using common usernames ("root", "admin", "user") and passwords ("123456", "1234"). (Seen across many IPs, with 162 counts for 'root' and 100+ for common passwords).
- **Scanning:** "mass scanner" IP reputation (448 counts), and "ET SCAN MS Terminal Server Traffic on Non-standard Port" (643 counts) indicates general scanning activity.
- **Common Bot Patterns:** "bot, crawler" IP reputation (3 counts) and general "Misc activity" (29456 counts) and "Misc Attack" (1215 counts) categories.

## 9) Infrastructure & Behavioral Classification
- **exploitation vs scanning:** Predominantly scanning and credential stuffing, with specific emerging n-day exploitation attempts.
- **campaign shape:** A mix of widespread spray (credential stuffing, general scanning) and more targeted exploitation attempts against specific CVEs.
- **infra reuse indicators:** IPs associated with "known attacker" and "mass scanner" reputations suggest infrastructure reuse. DigitalOcean and Google LLC ASNs are prominent, indicating use of cloud hosting for attack infrastructure.
- **odd-service fingerprints:** VNC (590X) services showing significant attention.

## 10) Evidence Appendix
- **CVE-2025-55182:**
    - Source IPs: (unavailable, aggregated)
    - ASNs: (unavailable, aggregated)
    - Target ports/services: (unavailable, aggregated)
    - Paths/endpoints: (unavailable, aggregated)
    - Payload/artifact excerpts: (unavailable, aggregated)
    - Staging indicators: (unavailable)
    - Temporal checks results: unavailable
- **CVE-2019-11500:**
    - Source IPs: (unavailable, aggregated)
    - ASNs: (unavailable, aggregated)
    - Target ports/services: (unavailable, aggregated)
    - Paths/endpoints: (unavailable, aggregated)
    - Payload/artifact excerpts: (unavailable, aggregated)
    - Staging indicators: (unavailable)
    - Temporal checks results: unavailable
- **Top Botnet Mapping - DigitalOcean, LLC (ASN 14061):**
    - Source IPs: (aggregated, e.g., 45.95.214.24, 136.114.97.84, etc.)
    - ASNs: ASN 14061
    - Target ports/services: Various, including 445, 22, 590X
    - Paths/endpoints: Various
    - Payload/artifact excerpts: (unavailable, aggregated)
    - Staging indicators: (unavailable)
    - Temporal checks results: unavailable
- **Top Botnet Mapping - Google LLC (ASN 396982):**
    - Source IPs: (aggregated)
    - ASNs: ASN 396982
    - Target ports/services: Various
    - Paths/endpoints: Various
    - Payload/artifact excerpts: (unavailable, aggregated)
    - Staging indicators: (unavailable)
    - Temporal checks results: unavailable

## 11) Indicators of Interest
- **IPs:** 45.95.214.24, 136.114.97.84, 46.19.137.194, 134.209.37.134, 64.225.65.145
- **CVEs:** CVE-2025-55182, CVE-2019-11500
- **Paths/Endpoints:** /, /.env, /.well-known/security.txt, /api/graphql, /bin/ (from Tanner honeypot)
- **Honeypot Usernames:** root, admin, user, 345gs5662d34, test
- **Honeypot Passwords:** 345gs5662d34, 3245gs5662d34, 1234, 123456, 12345678
- **Suricata Signatures:** GPL INFO VNC server response, ET SCAN MS Terminal Server Traffic on Non-standard Port

## 12) Backend Tool Issues
- No significant tool failures. The `url.path` field was not present, which limited direct correlation for URL paths in some general searches, but Tanner specific searches provided some path information.