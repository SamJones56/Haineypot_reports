# Investigation Report: 2026-03-06T12:00:05Z to 2026-03-06T15:00:05Z

## Investigation Scope
- investigation_start: 2026-03-06T12:00:05Z
- investigation_end: 2026-03-06T15:00:05Z
- completion_status: Complete
- degraded_mode: false

## Executive Triage Summary
- Total attacks: 24792 events.
- Top services/ports of interest: Port 445 (SMB), VNC (590x), MS Terminal Server (non-standard), ICS protocols (Kamstrup), Web (80, 3000-3012, 6060).
- Top confirmed known exploitation: Active exploitation attempts for CVE-2025-55182 (React Server Components React2Shell Unsafe Flight Protocol Property Access).
- Botnet/campaign mapping highlights: Wide-ranging scanning activity from DigitalOcean, Nettlinx, TE Data ASNs; concentrated attacks against CVE-2025-55182.
- Odd-service/minutia attacks: Conpot honeypot interactions with Kamstrup and Guardian AST protocols, Tanner honeypot attempts to access `.env` files.
- Credential stuffing attempts with common usernames ("root", "admin") and passwords (blank, "password").

## Candidate Discovery Summary
- Total attack events: 24792
- Top attacking countries: United States (7199), India (3702), Egypt (1674), Qatar (1397), Ukraine (1341)
- Top attacking source IPs: 202.53.65.178 (3109), 196.202.80.70 (1673), 178.153.127.226 (1397)
- Top attacking ASNs: DigitalOcean, LLC (5476), Nettlinx Limited (3109), TE Data (1673)
- Top alert categories: Misc activity (16945), Generic Protocol Command Decode (9395), Misc Attack (1274), Attempted Information Leak (935), Web Application Attack (151)
- Top CVEs: CVE-2025-55182 (144), CVE-2024-14007 (6), CVE-2021-3449 (3)
- Top input usernames: root (353), admin (191)
- Top input passwords: "" (241), "345gs5662d34" (106), "password" (48)
- Redis honeypot actions: Closed (12), NewConnect (12), info (6)
- Conpot protocols: kamstrup_protocol (21), guardian_ast (12)
- Tanner URIs: / (36), /.env (5)
- P0f OS distribution: Windows NT kernel (57446), Linux 2.2.x-3.x (29862)
- Source IP reputation: known attacker (8679), mass scanner (706)

## Emerging n-day Exploitation
- cve/signature mapping: CVE-2025-55182, "ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)"
- evidence summary: 144 events observed. Attackers used source IPs 24.144.94.222 and 193.32.162.28, targeting internal IP 10.17.0.5 on various ports (80, 3000-3012, 6060) with HTTP GET requests to paths like `/`, `/api`, `/_next`, `/api/route`, `/app`, `/_next/server`.
- affected service/port: Web application services on ports 80, 3000-3012, 6060.
- confidence: High
- operational notes: Active exploitation of a recently identified vulnerability in React Server Components. Further investigation into specific payload details for deeper analysis is recommended.

## Novel or Zero-Day Exploit Candidates
- No strong novel or zero-day exploit candidates were identified after comprehensive checks. The observed exploitation is well-mapped to existing CVEs and signatures.

## Botnet/Campaign Infrastructure Mapping
- item_id: CVE-2025-55182 related attacks
- campaign_shape: Targeted exploitation following potential reconnaissance.
- suspected_compromised_src_ips: 24.144.94.222, 193.32.162.28
- ASNs / geo hints: Not explicitly provided for these specific IPs in the current dataset, but likely cloud/hosting providers.
- suspected_staging indicators: No direct staging indicators observed, but the variety of paths accessed suggests an attempt to enumerate application structure.
- suspected_c2 indicators: No explicit C2 indicators.
- confidence: Medium (for infrastructure mapping)
- operational notes: Monitor source IPs 24.144.94.222 and 193.32.162.28 for continued activity.

- item_id: Mass scanning/commodity attacks
- campaign_shape: Spray-and-pray/opportunistic scanning.
- suspected_compromised_src_ips: 202.53.65.178 (3109), 196.202.80.70 (1673), 178.153.127.226 (1397)
- ASNs / geo hints: AS10225 (Nettlinx Limited, India), AS8452 (TE Data, Egypt), AS8781 (Ooredoo Q.S.C., Qatar). Also significant activity from DigitalOcean (AS14061, US).
- suspected_staging indicators: No specific staging indicators identified.
- suspected_c2 indicators: No explicit C2 indicators.
- confidence: High (for scanning activity)
- operational notes: Block known attacker IPs and monitor targeted ports (e.g., 445, 590x, RDP ports).

## Odd-Service / Minutia Attacks
- service_fingerprint: VNC (ports 5901, 5902, 5903, 5904, 5905)
- why it’s unusual/interesting: Traffic targeting VNC on multiple sequential ports indicates broad scanning for remote access services.
- evidence summary: 458 events on port 5902, 281 on 5903, 274 on 5901 from US IPs.
- confidence: High
- recommended monitoring pivots: Monitor VNC services for brute-force attempts and unauthorized access.

- service_fingerprint: Conpot ICS protocols (kamstrup_protocol, guardian_ast)
- why it’s unusual/interesting: Interaction with industrial control system honeypots suggests attackers are probing for or targeting ICS/OT environments.
- evidence summary: 21 events for `kamstrup_protocol`, 12 for `guardian_ast`.
- confidence: Medium
- recommended monitoring pivots: Monitor ICS/OT network segments for unusual probing or traffic.

- service_fingerprint: Tanner honeypot (HTTP paths)
- why it’s unusual/interesting: Attempts to access `.env` files are common for web application reconnaissance to find configuration details or credentials.
- evidence summary: 5 events for `/.env`, 2 events for `/.env.backup`, `/.env.container`, `/.env.dev`, `/.env.development`, `/.env.dist`, `/.env.docker`, `/.env.example`.
- confidence: High
- recommended monitoring pivots: Monitor web server logs for requests to sensitive configuration files like `.env`.

## Known-Exploit / Commodity Exclusions
- Credential Noise: Numerous attempts with common usernames (root, admin) and weak/blank passwords observed across many source IPs.
- Scanning Activity: Widespread scanning for VNC servers (GPL INFO VNC server response), MS Terminal Server traffic on non-standard ports (ET SCAN MS Terminal Server Traffic on Non-standard Port), and SMB (port 445) across various countries and ASNs.
- Generic Bot Patterns: High counts of "Misc activity" and "Generic Protocol Command Decode" alerts, indicating broad, automated scanning and enumeration.

## Infrastructure & Behavioral Classification
- Exploitation vs Scanning: Mixed. Significant mass scanning for common services (VNC, SMB, RDP) alongside targeted exploitation of CVE-2025-55182.
- Campaign shape: Broad spray-and-pray for commodity attacks (e.g., port 445 scans). More focused, but still seemingly automated, for the CVE-2025-55182 exploitation against varied web paths.
- Infra reuse indicators: Heavy use of cloud providers/VPS (DigitalOcean, Nettlinx) for attack infrastructure.
- Odd-service fingerprints: VNC, MS Terminal Server (non-standard), Redis, and ICS protocols (Kamstrup, Guardian AST).

## Evidence Appendix
- **CVE-2025-55182 Exploitation**
    - Source IPs with counts: 24.144.94.222 (many), 193.32.162.28 (many)
    - ASNs with counts: Missing specific ASN for these IPs in current dataset, but likely cloud/hosting.
    - Target ports/services: 80, 3000-3012, 6060 (HTTP/Web Application)
    - Paths/endpoints: `/`, `/api`, `/_next`, `/api/route`, `/app`, `/_next/server`
    - Payload/artifact excerpts: HTTP GET requests, Suricata alert signature: "ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)"
    - Staging indicators: Not directly observed in samples, but the sequential access to API/next paths suggests an application enumeration phase.
    - Temporal checks: Observed between 2026-03-06T14:53:58Z and 2026-03-06T14:55:48Z.

- **Top Botnet Activity (SMB Scanning)**
    - Source IPs with counts: 202.53.65.178 (3109), 196.202.80.70 (1673), 178.153.127.226 (1397)
    - ASNs with counts: AS10225 (Nettlinx Limited, India), AS8452 (TE Data, Egypt), AS8781 (Ooredoo Q.S.C., Qatar)
    - Target ports/services: 445 (SMB)
    - Paths/endpoints: Not applicable for SMB scanning.
    - Payload/artifact excerpts: Not explicitly captured in summary, but indicated by high volume on port 445.
    - Staging indicators: Missing.
    - Temporal checks: Occurred throughout the investigation window.

- **Path Traversal Attempts (Honeypot)**
    - Source IPs with counts: 10.17.0.5 (internal IP, likely honeypot interaction, total 10185 events with some path traversals)
    - ASNs with counts: Missing.
    - Target ports/services: Various HTTP ports.
    - Paths/endpoints: `/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd`, `/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd`
    - Payload/artifact excerpts: HTTP GET requests with encoded path traversal sequences.
    - Staging indicators: Missing.
    - Temporal checks: Observed within the investigation window.

## Indicators of Interest
- IPs:
    - 24.144.94.222 (CVE-2025-55182 related)
    - 193.32.162.28 (CVE-2025-55182 related)
    - 202.53.65.178 (Top SMB scanner)
    - 196.202.80.70 (Top SMB scanner)
    - 178.153.127.226 (Top SMB scanner)
- CVEs:
    - CVE-2025-55182
- Paths/URLs:
    - `/.env` (Tanner honeypot reconnaissance)
    - `/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd` (Path traversal)
    - `/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd` (Path traversal)
- Suricata Signatures:
    - "ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)"
    - "GPL INFO VNC server response"
    - "ET SCAN MS Terminal Server Traffic on Non-standard Port"
- Honeypot specific:
    - Conpot protocol: `kamstrup_protocol`
    - Conpot protocol: `guardian_ast`

## Backend Tool Issues
- The `top_src_ips_for_cve` tool returned empty buckets for `CVE-2025-55182`. This was likely due to the CVE being primarily identified within the `alert.signature` field rather than a dedicated `alert.cve_id` field that the tool directly aggregates from. This did not weaken conclusions as `suricata_signature_samples` provided the necessary evidence.