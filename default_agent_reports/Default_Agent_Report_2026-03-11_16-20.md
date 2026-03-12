# Threat Hunting Final Report: 2026-03-11

## 1) Investigation Scope
- **investigation_start**: 2026-03-11T16:00:05Z
- **investigation_end**: 2026-03-11T20:00:05Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true
  - **Reason**: Several data pipeline queries failed during the investigation. While workarounds were successful in some cases, key evidence, such as the full set of source IPs for an emerging n-day campaign (CVE-2025-55182), could not be retrieved.

## 2) Executive Triage Summary
- **Top Services of Interest**: High-volume activity was observed against web services (HTTP on ports 80 and 18080) and SMB (TCP/445). Additionally, low-volume but highly targeted reconnaissance was detected against niche Industrial Control System (ICS) protocols, including Guardian AST (TCP/10001) and IEC-104 (TCP/2404).
- **Top Confirmed Known Exploitation**: Two emerging n-day vulnerabilities were actively exploited:
    - **CVE-2025-55182 (React2Shell)**: A critical RCE in React Server Components, observed from a single source IP.
    - **CVE-2024-4577 (PHP Argument Injection)**: Probing for a critical PHP vulnerability from a single source IP.
- **Top Unmapped Exploit-like Items**: No unmapped novel exploit candidates were identified in this window; all significant exploit-like activity was successfully mapped to existing CVEs.
- **Botnet/Campaign Mapping Highlights**: A large-scale, coordinated SMB (TCP/445) scanning campaign was identified, originating from two distinct sources: `41.35.120.170` (Egypt) and `200.105.151.2` (Bolivia). The activity appears to be reconnaissance.
- **Major Uncertainties**: The full scope of the CVE-2025-55182 exploitation campaign is unknown due to a backend query failure that prevented the enumeration of all participating source IPs.

## 3) Candidate Discovery Summary
- The discovery process successfully merged baseline, known signal, credential, and honeypot-specific data streams.
- Five initial candidates were seeded for deeper validation, covering emerging n-day exploitation, known exploit scanning, botnet-like infrastructure, and odd-service targeting.
- Initial queries to correlate Suricata alerts with source IPs were successful, but queries against honeypot-specific logs (Conpot) initially failed, requiring workarounds in the validation phase.

## 4) Emerging n-day Exploitation

### CVE-2025-55182: React2Shell RCE
- **cve/signature mapping**: CVE-2025-55182 / `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
- **evidence summary**:
    - **Total Events**: 162
    - **Source IPs**: `195.3.221.86` (Note: Only IP found in samples; aggregation query failed)
    - **Targeted Paths**: `/_next`, `/api`, `/app`, `/_next/server`, `/api/route`
- **affected service/port**: HTTP / TCP 18080 (Likely a web app using React/Next.js)
- **confidence**: High
- **operational notes**: Activity matches a recently disclosed, critical RCE (CVSS 10.0). Although only one source IP was confirmed from event samples, the campaign could be larger. The query failure for source IP aggregation is a significant visibility gap.

### CVE-2024-4577: PHP Argument Injection Probe
- **cve/signature mapping**: CVE-2024-4577
- **evidence summary**:
    - **Total Events**: 1
    - **Source IP**: `163.7.3.156`
    - **Key Artifact**: The URI query `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` uses a soft-hyphen (`%AD`) for argument injection, a specific signature of this exploit.
- **affected service/port**: HTTP / TCP 80
- **confidence**: High
- **operational notes**: This is a probe (GET request) for a known, critical RCE affecting PHP in CGI mode on Windows. The same source IP conducted other unrelated exploit probes. A Suricata signature should be created for this specific URI pattern.

## 6) Botnet/Campaign Infrastructure Mapping

### SMB (TCP/445) Scanning Campaign
- **item_id**: 4b6a9e10-3c2b-4d57-9d7a-5a2b1f1e9c9d
- **campaign_shape**: spray (High-volume, single-port scanning from a few sources to many destinations)
- **suspected_compromised_src_ips**:
    - `41.35.120.170` (3,147 events)
    - `200.105.151.2` (861 events)
- **ASNs / geo hints**:
    - AS8452 / TE Data (Egypt)
    - AS26210 / AXS Bolivia S. A. (Bolivia)
- **suspected_staging indicators**: None identified.
- **suspected_c2 indicators**: None identified.
- **confidence**: High
- **operational notes**: This is a large-scale reconnaissance campaign. The activity did not trigger any existing IDS signatures, suggesting it is simple port scanning without exploit payloads. Monitor these IPs for changes in tactics.

## 7) Odd-Service / Minutia Attacks

### Industrial Control System (ICS) Protocol Scanning
- **service_fingerprint**:
    - `guardian_ast` on TCP/10001 (Veeder-Root Gas Tank Monitor)
    - `IEC104` on TCP/2404 (Telecontrol Protocol)
    - `kamstrup_protocol` (port/IP unknown)
- **why it’s unusual/interesting**: This activity indicates targeted reconnaissance against non-standard, potentially high-value industrial systems. The `guardian_ast` protocol is highly specific and not typically seen in general internet noise.
- **evidence summary**:
    - **Total Events**: 29
    - **Key Protocols**: `guardian_ast` (24), `IEC104` (4), `kamstrup_protocol` (1)
    - **Source IPs**: `16.58.56.214`, `85.217.149.63`, `204.76.203.233`, `9.234.10.182`
- **confidence**: High
- **recommended monitoring pivots**: Add identified source IPs to a watchlist for ICS-related activity. Investigate the data pipeline for the Conpot honeypot to ensure full visibility.

## 8) Known-Exploit / Commodity Exclusions
- **Known Vulnerability Scanning**: A single probe for **CVE-2017-9841** (PHPUnit RCE) was observed from `163.7.3.156`. This is opportunistic scanning for an old, well-known vulnerability.
- **VNC Scanning**: High-volume traffic (16,691 events) across VNC-related ports (5901-5907) triggered the generic signature `GPL INFO VNC server response`. This is classified as commodity scanning noise.
- **Credential Noise**: Standard brute-force attempts were observed with common usernames (`root`, `admin`) and passwords (`123`, `123456`). This activity is low-priority background noise.
- **Generic Web Scanning**: Probes for common sensitive files like `/.env` and `/admin/config.php` were observed from multiple sources and are considered low-signal, automated scanning.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The investigation identified both active n-day exploitation (CVE-2025-55182, CVE-2024-4577) and large-scale reconnaissance scanning (SMB, VNC, ICS).
- **Campaign Shape**:
    - **Spray**: The SMB scanning campaign on port 445 fits this pattern.
    - **Fan-out**: The CVE-2025-55182 activity, originating from a single source, is consistent with this shape.
- **Infra Reuse Indicators**: The IP `163.7.3.156` was used to probe for at least two distinct PHP vulnerabilities (CVE-2024-4577 and CVE-2017-9841), indicating reuse of infrastructure for multiple exploit attempts.
- **Odd-Service Fingerprints**: Targeted activity against specific ICS protocols (`guardian_ast`, `IEC104`) on non-standard ports was confirmed.

## 10) Evidence Appendix

### Emerging n-day: CVE-2025-55182 (React2Shell)
- **Source IPs**: `195.3.221.86`
- **ASNs**: [Data Unavailable]
- **Target Ports/Services**: TCP/18080 (HTTP)
- **Paths/Endpoints**: `/_next`, `/api`, `/app`, `/_next/server`, `/api/route`
- **Payload/Artifact Excerpts**: Suricata Signature: `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
- **Temporal Checks**: Unavailable (Query for full source IP list failed).

### Emerging n-day: CVE-2024-4577 (PHP Injection)
- **Source IPs**: `163.7.3.156`
- **ASNs**: 150436 (Byteplus Pte. Ltd.)
- **Target Ports/Services**: TCP/80 (HTTP)
- **Paths/Endpoints**: `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
- **Payload/Artifact Excerpts**: Use of soft-hyphen `%AD` for argument injection.
- **Temporal Checks**: Single event observed in the time window.

### Botnet Mapping: SMB Scanning
- **Source IPs**: `41.35.120.170` (3147), `200.105.151.2` (861)
- **ASNs**: 8452 (TE Data), 26210 (AXS Bolivia S. A.)
- **Target Ports/Services**: TCP/445 (SMB)
- **Payload/Artifact Excerpts**: No payload detected; activity consists of connection attempts (Suricata flow events).
- **Temporal Checks**: Sustained activity throughout the investigation window.

### Odd-Service: ICS Scanning
- **Source IPs**: `16.58.56.214`, `85.217.149.63`, `204.76.203.233`, `9.234.10.182`
- **ASNs**: 16509 (Amazon), 209334 (Modat B.V.), 51396 (Pfcloud UG), 8075 (Microsoft)
- **Target Ports/Services**: TCP/10001 (`guardian_ast`), TCP/2404 (`IEC104`)
- **Payload/Artifact Excerpts**: Connection attempts only; no command/control data observed.
- **Temporal Checks**: Sporadic connections throughout the investigation window.

## 11) Indicators of Interest
- **CVEs**: `CVE-2025-55182`, `CVE-2024-4577`
- **Source IPs (Exploitation/Probing)**:
    - `195.3.221.86` (React2Shell)
    - `163.7.3.156` (PHP Probes)
- **Source IPs (Botnet/Scanning)**:
    - `41.35.120.170` (SMB Scan)
    - `200.105.151.2` (SMB Scan)
- **Source IPs (ICS Scanning)**:
    - `16.58.56.214`
    - `85.217.149.63`
    - `204.76.203.233`
    - `9.234.10.182`
- **URIs / Paths**:
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    - `/_next/server`
    - `/api/route`

## 12) Backend Tool Issues
- **`top_src_ips_for_cve`**: This tool failed when querying for source IPs related to `CVE-2025-55182`. It returned an empty aggregation bucket despite 162 events being present.
  - **Impact**: This failure prevented a full assessment of the campaign's scale, weakening the conclusion which had to rely on a single IP identified from raw samples.
- **`custom_basic_search`**: The query to find all source IPs targeting port 445 failed, likely due to a syntax issue.
  - **Impact**: This weakened the botnet analysis, which relied on baseline data rather than a fresh, confirmed aggregation.
- **`kibanna_discover_query` / `two_level_terms_aggregated` for Conpot**: Initial queries for `type.keyword: Conpot` failed to return any data. A later attempt using `type.keyword: ConPot` (case-sensitive) succeeded.
  - **Impact**: The initial failure blocked the analysis of the ICS activity. The successful workaround allowed validation to proceed, but it highlights a potential data consistency issue.

## 13) Agent Action Summary (Audit Trail)

- **agent_name**: ParallelInvestigationAgent
- **purpose**: To run baseline data collection agents in parallel.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Executed Baseline, KnownSignal, CredentialNoise, and HoneypotSpecific agents.
- **key_results**: Produced four structured JSON outputs detailing the overall activity in the time window.
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: To merge parallel outputs and generate high-level candidate seeds for investigation.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**: Merged inputs, triaged high-volume vs. high-interest signals, pivoted on CVEs and unique Tanner paths using `two_level_terms_aggregated`.
- **key_results**: Generated 5 candidate seeds for emerging threats, botnet infrastructure, and odd-service attacks.
- **errors_or_gaps**: Experienced some query failures (`suricata_lenient_phrase_search`, `two_level_terms_aggregated` for Conpot) that created minor evidence gaps passed to the validation stage.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: To validate or invalidate each discovery seed through deep-dive queries and analysis.
- **inputs_used**: `candidate_seeds`.
- **actions_taken**: Ran 5 iterations, one for each candidate. Utilized tools like `top_src_ips_for_cve`, `kibanna_discover_query`, `suricata_cve_samples`, and `search`. A second iteration was performed on the 'odd_service' candidate to resolve initial query failures.
- **key_results**:
    - Validated 2 emerging n-day exploitation campaigns (CVE-2025-55182, CVE-2024-4577).
    - Mapped a 2-IP SMB scanning campaign.
    - Validated targeted scanning of niche ICS protocols.
    - Re-classified one candidate as known/commodity scanning (CVE-2017-9841).
- **errors_or_gaps**: Encountered and logged multiple query failures, most notably the inability to aggregate all source IPs for CVE-2025-55182.

- **agent_name**: OSINTAgent
- **purpose**: To enrich validated candidates with public intelligence.
- **inputs_used**: `validated_candidates`.
- **actions_taken**: Performed `search` queries for all identified CVEs and key source IPs.
- **key_results**: Confirmed that the "emerging" CVEs were publicly known and actively exploited n-days. Found public documentation of scanning activity from network blocks associated with the ICS attackers. Produced a structured JSON output with findings for each candidate.
- **errors_or_gaps**: OSINT on the SMB scanning IPs was inconclusive.

- **agent_name**: ReportAgent
- **purpose**: To compile the final report from all workflow state outputs.
- **inputs_used**: `investigation_start`, `investigation_end`, `validated_candidates`, `osint_validation_result`, and all intermediate agent outputs.
- **actions_taken**: Consolidated all evidence, applied mandatory reporting logic, and generated this markdown report.
- **key_results**: This report.
- **errors_or_gaps**: None.

- **agent_name**: SaveReportAgent
- **purpose**: To save the final report artifact.
- **inputs_used**: Final report content.
- **actions_taken**: Called the `default_write_file` tool.
- **key_results**: File write action initiated.
- **errors_or_gaps**: None.