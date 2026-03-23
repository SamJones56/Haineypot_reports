Investigation Scope
- investigation_start: 2026-03-04T06:00:04Z
- investigation_end: 2026-03-04T07:00:04Z
- completion_status: Complete
- degraded_mode: false

Executive Triage Summary
- Top services/ports of interest include SMB (port 445), SSH (port 22), VNC (ports 5901-5926), and HTTP (port 80).
- Confirmed known exploitation includes "GPL INFO VNC server response" and "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" signatures.
- High volume of "Generic Protocol Command Decode" and "Misc activity" alerts.
- Credential stuffing attempts with common usernames like "root" and passwords like "123456".
- Significant activity from "known attacker" source IPs.
- Very low activity observed on Redis, Adbhoney, and Conpot honeypots, suggesting they were not primary targets during this period.
- Tanner honeypot captured various web resource requests, including potential directory traversal attempts like "/.env".

Candidate Discovery Summary
- Total attack events: 11326
- Top attacking countries: Netherlands (2718), France (2628), United States (2008), Bolivia (1803), Germany (659).
- Top attacking IPs: 164.92.155.68 (2622), 79.98.102.166 (2568), 200.105.151.2 (1803).
- Missing inputs/errors: `url_path` field was not present in the field presence check.

Emerging n-day Exploitation
- cve/signature mapping: CVE-2019-11500, CVE-2021-3449, CVE-2024-14007 (3 counts each)
  - evidence summary: Each CVE detected 3 times. Specific details of exploitation attempts for these CVEs are not available from the current tools without deeper analysis.
  - affected service/port: Not explicitly available from the CVE aggregation.
  - confidence: Medium (based on signature matches)
  - operational notes: Monitor for specific exploitation attempts related to these CVEs.

- cve/signature mapping: ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (Signature ID: 2024766)
  - evidence summary: 1303 alerts. This signature indicates attempts to install the DoublePulsar backdoor.
  - affected service/port: Typically associated with SMB (port 445) exploitation.
  - confidence: High
  - operational notes: Investigate source IPs associated with this signature for active exploitation and potential compromise.

Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
- No strong evidence for novel or zero-day exploit candidates found during this investigation.

Botnet/Campaign Infrastructure Mapping
- item_id: N/A
- campaign_shape: Spray/Scanning (indicated by widespread "GPL INFO VNC server response" and "SURICATA IPv4 truncated packet" signatures, and diverse source IPs/countries targeting various ports). Also, potential fan-out activity from specific IPs targeting SMB.
- suspected_compromised_src_ips:
    - 164.92.155.68 (2622 counts)
    - 79.98.102.166 (2568 counts)
    - 200.105.151.2 (1803 counts)
- ASNs / geo hints:
    - Netherlands (from 164.92.155.68)
    - France (from 79.98.102.166)
    - Bolivia (from 200.105.151.2)
- suspected_staging indicators: Not explicitly identified, but paths like "/.env" on Tanner honeypot could indicate attempts to discover sensitive configuration files.
- suspected_c2 indicators: Not explicitly identified.
- confidence: Medium (based on high volume of known attacker IPs and commodity exploitation signatures)
- operational notes: Block identified malicious IPs; monitor for outbound connections from compromised hosts to newly observed domains/IPs.

Odd-Service / Minutia Attacks
- service_fingerprint: VNC (ports 5901-5926)
  - why it’s unusual/interesting: High volume of VNC server responses (2551 counts of "GPL INFO VNC server response" signature) indicating scanning or probing activity against VNC services, potentially targeting default credentials or known vulnerabilities.
  - evidence summary: 2551 alerts of "GPL INFO VNC server response". Attacked from various countries including United States (267 counts on port 5925, 265 on 5926), Australia, and Bulgaria.
  - confidence: High
  - recommended monitoring pivots: Monitor VNC services for brute-force attempts, unusual login failures, and connections from suspicious IPs.

- service_fingerprint: SMB (port 445)
  - why it’s unusual/interesting: High volume of activity, including "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" and significant traffic from France and Bolivia.
  - evidence summary: 1303 alerts for DoublePulsar. France (2568 counts on port 445), Bolivia (1803 counts on port 445).
  - confidence: High
  - recommended monitoring pivots: Monitor SMB services for suspicious file access, execution of unusual commands, and connections from known malicious IPs.

- service_fingerprint: SSH (port 22)
  - why it’s unusual/interesting: Multiple input usernames and passwords indicate credential stuffing or brute-force attempts.
  - evidence summary: Top usernames "root" (195), "postgres" (63), "user" (17). Top passwords "123456" (58), "password" (19). Netherlands and Germany are top attacking countries for SSH.
  - confidence: High
  - recommended monitoring pivots: Monitor SSH logs for failed login attempts, unusual login patterns, and access from blacklisted IPs. Implement stronger authentication mechanisms.

Known-Exploit / Commodity Exclusions
- Credential noise: Numerous attempts to log in with common usernames ("root", "admin", "test") and weak passwords ("123456", "password", "123") across various services, primarily SSH.
- Scanning: Widespread scanning activity indicated by "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet" signatures, as well as the high volume of VNC server response alerts and diverse country-to-port mappings.
- Known bot patterns: Activity from "known attacker" IPs and signatures like "ET DROP Dshield Block Listed Source group 1" point to commodity botnet activity.

Infrastructure & Behavioral Classification
- exploitation vs scanning: Both exploitation attempts (DoublePulsar, potential CVEs) and widespread scanning (VNC, SSH) are observed.
- campaign shape: Predominantly spray/scanning, with some targeted exploitation attempts.
- infra reuse indicators: Top attacking IPs and ASNs show consistent activity within the reporting window, suggesting organized infrastructure.
- odd-service fingerprints: VNC services are a notable target.

Evidence Appendix
- **Emerging n-day Exploitation (CVE-2019-11500, CVE-2021-3449, CVE-2024-14007)**
    - source IPs with counts: Not directly available per CVE from current tools.
    - ASNs with counts: Not directly available per CVE from current tools.
    - target ports/services: Not directly available per CVE from current tools.
    - paths/endpoints: Not directly available per CVE from current tools.
    - payload/artifact excerpts: Missing (telemetry-derived)
    - staging indicators: Missing
    - temporal checks results: unavailable

- **Emerging n-day Exploitation (ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication)**
    - source IPs with counts: Not directly available from signature alone, requires deeper analysis.
    - ASNs with counts: Not directly available.
    - target ports/services: Port 445 (SMB)
    - paths/endpoints: Not explicitly available.
    - payload/artifact excerpts: Missing (telemetry-derived)
    - staging indicators: Missing
    - temporal checks results: unavailable

- **Botnet/Campaign Infrastructure Mapping (Top Attacking IPs)**
    - source IPs with counts: 164.92.155.68 (2622), 79.98.102.166 (2568), 200.105.151.2 (1803)
    - ASNs with counts: Not directly available, but associated with Netherlands, France, Bolivia.
    - target ports/services: Various, including 445 (SMB), 22 (SSH), 59xx (VNC)
    - paths/endpoints: Not explicitly available for all IPs, but Tanner honeypot showed paths like "/" and "/.env".
    - payload/artifact excerpts: Not directly available.
    - staging indicators: Not explicitly identified.
    - temporal checks results: unavailable

- **Odd-Service / Minutia Attacks (VNC)**
    - source IPs with counts: Various, including United States IPs.
    - ASNs with counts: Not directly available.
    - target ports/services: 5901-5926
    - paths/endpoints: Not applicable for VNC server responses.
    - payload/artifact excerpts: "GPL INFO VNC server response" (signature)
    - staging indicators: Missing
    - temporal checks results: unavailable

Indicators of Interest
- IPs: 164.92.155.68, 79.98.102.166, 200.105.151.2
- CVEs: CVE-2019-11500, CVE-2021-3449, CVE-2024-14007
- Signatures: "GPL INFO VNC server response", "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication", "ET SCAN MS Terminal Server Traffic on Non-standard Port", "ET DROP Dshield Block Listed Source group 1"
- Paths: "/.env", "/wp-includes/js/jquery/jquery.js,qver=1.12.4.pagespeed.jm.pPCPAKkkss.js", "/robots.txt"
- Usernames: "root", "postgres", "user", "oracle", "ubuntu"
- Passwords: "123456", "password", "123", "P@ssw0rd", "p@ssw0rd"

Backend Tool Issues
- No backend tool failures observed.