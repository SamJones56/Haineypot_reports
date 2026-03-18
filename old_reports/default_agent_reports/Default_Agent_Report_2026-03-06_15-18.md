1) Investigation Scope
- **investigation_start**: 2026-03-06T15:00:06Z
- **investigation_end**: 2026-03-06T18:00:06Z
- **completion_status**: Partial
- **degraded_mode**: true - Multiple backend tool failures affected the granularity of candidate validation and correlation, particularly for IP-to-event mapping for CVE-2025-55182 and ADBHoney malware.

2) Executive Triage Summary
- Total 19643 attacks observed in the 3-hour window.
- High volume commodity VNC scanning (16516 events on ports 5900, 5902, 5903) from various IPs, notably from the United States.
- Emerging n-day exploitation for **CVE-2025-55182 (React2Shell)** detected 119 times, characterized by POST / requests from DigitalOcean infrastructure (24.144.94.222) targeting multiple web ports (80, 443, 3000-3012). OSINT confirms this is a critical, actively exploited RCE.
- ADBHoney honeypot recorded 3 unique malware samples (6 total downloads) from multiple source IPs, indicating ongoing botnet activity, but specific IP-to-sample correlation was blocked by tool errors.
- Common web exploitation techniques (path traversal to `/etc/passwd`, sensitive file disclosures like `.env`, `/api/backup`, `/client_secret.json`) were observed across Tanner honeypot, ElasticPot, and Suricata, originating from multiple ASNs (China Mobile, Pfcloud UG, Amarutu Technology, Iomart Cloud, Hostglobal.plus, Latitude.sh). While initially flagged as a novel candidate, OSINT confirms these are well-known scanner tactics.
- Persistent backend tool failures (e.g., `kibanna_discover_query`, `two_level_terms_aggregated`) prevented precise source IP-to-exploit/malware correlation for key findings.

3) Candidate Discovery Summary
A total of 19643 attacks were observed.
Top areas of interest:
- Widespread VNC scanning: 16516 events, primarily targeting ports 5900, 5902, 5903.
- CVE-2025-55182 exploitation: 119 events with associated signature 'ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access'.
- Credential brute-forcing: High volume against common usernames (root, admin) and weak passwords.
- ADBHoney malware downloads: 6 total downloads of 3 unique samples.
- Tanner honeypot activity: Path traversal attempts and requests for sensitive files (e.g., `/.env`, `/api/backup`, `/client_secret.json`).

Several inputs were present (baseline, known signals, credential noise, honeypot specific). However, discovery was materially affected by repeated tool errors:
- `kibanna_discover_query` consistently failed for raw event inspection.
- `top_src_ips_for_cve` returned 0 results for CVE-2025-55182 despite its confirmed presence.
- `two_level_terms_aggregated` failed to provide specific source IP to malware or detailed signature to port correlations.
- `complete_custom_search` also failed, hindering detailed contextual analysis.

4) Emerging n-day Exploitation
- **Item ID**: END-001
    - **CVE/signature mapping**: CVE-2025-55182 (React2Shell), Signature: ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)
    - **Evidence summary**: 119 occurrences. Source IP 24.144.94.222 (DigitalOcean, LLC) engaged in high-volume POST / requests, targeting various web ports (80, 443, 3000-3012) using `Go-http-client/1.1` user agent.
    - **Affected service/port**: HTTP/Web (multiple non-standard ports, including 80, 443, 3000-3012)
    - **Confidence**: High
    - **Operational notes**: This is a critical, recently disclosed RCE vulnerability (CVSS 10.0) with known public exploits, actively leveraged by threat actors. Immediate patching is recommended. While detailed IP/port correlation was challenging due to tool limitations, the pattern from 24.144.94.222 suggests opportunistic scanning for this vulnerability.

5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
No truly novel exploit candidates were identified after OSINT validation. Candidate NEC-001, initially flagged as novel, was reclassified as Known-Exploit / Commodity Exclusions due to mapping to well-known Suricata signatures and common scanning techniques.

6) Botnet/Campaign Infrastructure Mapping
- **Item ID**: BCM-001
    - **Campaign shape**: Unknown (spray pattern inferred from multiple IPs accessing ADBHoney, direct C2/staging not identifiable with current data).
    - **Suspected compromised src_ips**:
        - 87.121.84.24 (Vpsvault.host Ltd, US) - 28 ADBHoney events
        - 135.237.126.219 (Unknown ASN) - 4 ADBHoney events
        - 20.80.88.209 (Unknown ASN) - 4 ADBHoney events
        - 172.245.21.30 (Unknown ASN) - 3 ADBHoney events
        - 91.196.152.117 (Unknown ASN) - 2 ADBHoney events
        - 91.196.152.119 (Unknown ASN) - 2 ADBHoney events
    - **ASNs / geo hints**: Vpsvault.host Ltd (US). Other IPs lack detailed ASN info but suggest geographically diverse sources.
    - **Suspected staging indicators**:
        - Malware sample filenames: `dl/689b47e85e5f2dde8c935d6b05b6a2db1d7d1686ee158b84e34e86f787844b21.raw` (4 counts), `dl/1c76974356d1f3fed12da57a50439a636073236e72084a890ba2c05d70b0826a.raw` (1 count), `dl/6d1cdb687c2a2f9b75aedefbad314a98203d5066df5b51e74a2748cec9cdd8f9.raw` (1 count).
        - Supporting evidence: Downloads observed on ADBHoney honeypot.
    - **Suspected c2 indicators**: None directly identified; malware download sources could potentially be staging or C2. Uncertainty: High.
    - **Confidence**: Medium (Provisional: true - due to tool limitations blocking IP-to-sample correlation and inconclusive OSINT on malware hashes).
    - **Operational notes**: Malware downloaded to ADBHoney. Further analysis of samples and source IPs is recommended. Monitor identified IPs for continued ADBHoney activity or other suspicious behavior. Resolve tool issues to improve correlation.

7) Odd-Service / Minutia Attacks
- **Service fingerprint**: ADBHoney
    - **Why it’s unusual/interesting**: ADBHoney targets Android Debug Bridge (ADB), which is often exposed on IoT/embedded devices. Malware downloads indicate active campaigns targeting this specific service, representing attacks against an 'odd' or non-standard enterprise service.
    - **Evidence summary**: 6 malware downloads of 3 unique samples. Source IPs from various providers (e.g., Vpsvault.host Ltd). No specific input commands captured, suggesting direct file transfer attempts or limited interaction.
    - **Confidence**: High
    - **Recommended monitoring pivots**: Monitor for ADB activity on non-standard ports, look for known ADB malware hashes, and track source IPs for recurring patterns.

8) Known-Exploit / Commodity Exclusions
- **Commodity VNC Scanning**: High volume (16516 counts) of 'GPL INFO VNC server response' activity observed on typical VNC ports (5900, 5902, 5903). This is routine internet background noise from a large number of IPs, primarily from the United States.
- **Commodity SSH/RDP Scanning**: Includes 'ET SCAN MS Terminal Server Traffic on Non-standard Port' (608 counts) and 'ET INFO SSH session in progress on Expected Port' (374 counts). These represent standard, widespread scanning and brute-force attempts for common remote access services.
- **Common Credential Brute-forcing**: Evidenced by frequent attempts with default/weak usernames (e.g., 'root', 'admin', 'ubuntu') and passwords (e.g., '123', '123456', 'password'). This is commodity noise indicative of automated credential stuffing and dictionary attacks.
- **Common Path Traversal and Sensitive File Access**: (Candidate NEC-001 reclassified here)
    - **Evidence**: Confirmed path traversal attempts targeting `/etc/passwd` (e.g., `/%2E%2E%2F.../etc/passwd`, `/..%2F..%2F.../etc/passwd`) captured on Tanner, Suricata, and ElasticPot. Attempts to access sensitive files like `/.env`, `/api/backup`, and `/client_secret.json` were also observed on Tanner.
    - **Justification**: Suricata signatures `ET WEB_SERVER /etc/passwd Detected in URI` (ID 2049400) and `ET INFO Request to Hidden Environment File - Inbound` (ID 2031502) explicitly detect these patterns. OSINT confirms these are well-documented, established web exploitation techniques commonly used by scanners and exploit tooling. While operationally interesting due to the variety of paths/files, the techniques themselves are not novel.

9) Infrastructure & Behavioral Classification
- **Exploitation vs. Scanning**:
    - CVE-2025-55182: Confirmed exploitation attempts (POST / with specific user agent).
    - ADBHoney: Malware downloads, likely post-exploitation or direct delivery via exposed service.
    - VNC/SSH/RDP: Predominantly scanning and brute-forcing.
    - Path Traversal/Sensitive File Access: Primarily scanning/reconnaissance attempts for information disclosure, potentially pre-exploitation.
- **Campaign Shape**:
    - CVE-2025-55182: Fan-out from 24.144.94.222 (DigitalOcean).
    - ADBHoney malware: Appears as a spray from multiple distinct source IPs.
    - Path Traversal/Sensitive File Access: Observed as a spray pattern from various IPs and ASNs across different honeypot types.
    - VNC/SSH/RDP: Broad, opportunistic internet scanning.
- **Infra Reuse Indicators**:
    - DigitalOcean (ASN 14061) observed in both general baseline scanning and specific CVE-2025-55182 activity.
    - China Mobile Communications Group (ASN 9808) observed in path traversal attempts.
    - Various other cloud/hosting providers associated with commodity scanning and sensitive file access.
- **Odd-Service Fingerprints**:
    - ADBHoney traffic (IoT/embedded context).
    - Non-standard HTTP ports (3000-3012) targeted by CVE-2025-55182 exploitation.

10) Evidence Appendix
- **Emerging n-day Exploitation (END-001: CVE-2025-55182)**
    - **Source IPs with counts**: 24.144.94.222 (119 CVE-related events, 746 total events from this IP)
    - **ASNs with counts**: 14061 (DigitalOcean, LLC)
    - **Target ports/services**: HTTP/Web on 80, 443, 3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010, 3011, 3012
    - **Paths/endpoints**: `/` (POST requests)
    - **Payload/artifact excerpts**: `http_user_agent: 'Go-http-client/1.1'`, `http_method: 'POST'`
    - **Staging indicators**: None directly identified.
    - **Temporal checks results**: Detected within the current 3-hour window.

- **Botnet/Campaign Infrastructure Mapping (BCM-001: ADBHoney Malware)**
    - **Source IPs with counts**: 87.121.84.24 (28 events), 135.237.126.219 (4 events), 20.80.88.209 (4 events), 172.245.21.30 (3 events), 91.196.152.117 (2 events), 91.196.152.119 (2 events)
    - **ASNs with counts**: 215925 (Vpsvault.host Ltd) associated with 87.121.84.24. Other ASNs unavailable.
    - **Target ports/services**: ADBHoney service.
    - **Paths/endpoints**: Malware download paths: `dl/689b47e85e5f2dde8c935d6b05b6a2db1d7d1686ee158b84e34e86f787844b21.raw`, `dl/1c76974356d1f3fed12da57a50439a636073236e72084a890ba2c05d70b0826a.raw`, `dl/6d1cdb687c2a2f9b75aedefbad314a98203d5066df5b51e74a2748cec9cdd8f9.raw`.
    - **Payload/artifact excerpts**: Malware file hashes (SHA256).
    - **Staging indicators**: Malware download endpoints from the honeypot itself.
    - **Temporal checks results**: Detected within the current 3-hour window.

- **Known-Exploit / Commodity Exclusions (NEC-001: Path Traversal/Sensitive File Access)**
    - **Source IPs with counts**:
        - Path Traversal: 204.76.203.73 (Pfcloud UG (haftungsbeschrankt)), 89.42.231.182 (Amarutu Technology Ltd), 117.188.115.86 (China Mobile), 117.188.30.65 (China Mobile)
        - Sensitive Files: 81.168.83.103 (Iomart Cloud Services Limited), 78.153.140.39 (Hostglobal.plus Ltd), 67.213.118.179 (Latitude.sh)
    - **ASNs with counts**: 51396 (Pfcloud UG), 206264 (Amarutu Technology Ltd), 9808 (China Mobile), 20860 (Iomart Cloud Services Limited), 202306 (Hostglobal.plus Ltd), 396356 (Latitude.sh)
    - **Target ports/services**: HTTP/Web on 80, 8081, 8181, 9200
    - **Paths/endpoints**:
        - Path Traversal: `/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd`, `/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd`, `/export/classroom-course-statistics?fileNames[]=../../../../../../../etc/passwd`, `/vpn/user/download/client?ostype=../../../../../../../../../etc/passwd`
        - Sensitive Files: `/.env`, `/api/backup`, `/client_secret.json`
    - **Payload/artifact excerpts**: `http_method: 'GET'`, User Agents: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:146.0) Gecko/20100101 Firefox/146.0`, `Go-http-client/1.1`, various other browser-like UAs.
    - **Staging indicators**: None directly identified.
    - **Temporal checks results**: Detected within the current 3-hour window.

11) Indicators of Interest
- **IPs**:
    - 24.144.94.222 (DigitalOcean, LLC) - Source of CVE-2025-55182 exploitation attempts.
    - 87.121.84.24 (Vpsvault.host Ltd) - Top source of ADBHoney activity.
    - 204.76.203.73 (Pfcloud UG (haftungsbeschrankt)) - Source of path traversal attempts.
    - 81.168.83.103 (Iomart Cloud Services Limited) - Source of sensitive file access (`.env`, `client_secret.json`).
- **Malware Hashes (SHA256)**:
    - `689b47e85e5f2dde8c935d6b05b6a2db1d7d1686ee158b84e34e86f787844b21`
    - `1c76974356d1f3fed12da57a50439a636073236e72084a890ba2c05d70b0826a`
    - `6d1cdb687c2a2f9b75aedefbad314a98203d5066df5b51e74a2748cec9cdd8f9`
- **CVEs**:
    - CVE-2025-55182 (React Server Components RCE)
- **Suricata Signatures**:
    - `2100560` (GPL INFO VNC server response)
    - `2023753` (ET SCAN MS Terminal Server Traffic on Non-standard Port)
    - `2066027` (ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182))
    - `2049400` (ET WEB_SERVER /etc/passwd Detected in URI)
    - `2031502` (ET INFO Request to Hidden Environment File - Inbound)
- **Paths/Endpoints**:
    - `/` (POST requests for CVE-2025-55182)
    - `/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd`
    - `/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd`
    - `/.env`
    - `/api/backup`
    - `/client_secret.json`
- **User Agent**: `Go-http-client/1.1` (associated with CVE-2025-55182 exploitation)

12) Backend Tool Issues
- **kibanna_discover_query**:
    - **Failure reason**: Repeated 'Expected text at 1:71 but found START_ARRAY' error (status code 400).
    - **Affected validations**: Blocked direct raw event inspection for various terms (CVE IDs, honeypot types, specific file names) which hampered precise correlation and detailed contextual analysis for END-001, BCM-001, and NEC-001.
- **top_src_ips_for_cve**:
    - **Failure reason**: Returned 0 results for CVE-2025-55182 despite the CVE's presence being confirmed by other tools.
    - **Affected validations**: Prevented aggregated source IP and destination port analysis for CVE-2025-55182 (END-001).
- **two_level_terms_aggregated**:
    - **Failure reason**: Returned no secondary buckets for several critical aggregations (e.g., alert.signature.keyword to src_ip.keyword, adbhoney.file_name.keyword to src_ip.keyword, alert.signature.keyword to dest_port.keyword).
    - **Affected validations**: Severely limited the ability to correlate source IPs with specific ADBHoney malware samples (BCM-001) and to precisely map source IPs and destination ports for Suricata alerts.
- **complete_custom_search**:
    - **Failure reason**: 'Expected [START_OBJECT] but found [VALUE_STRING]' error (status code 400).
    - **Affected validations**: Blocked custom Elasticsearch queries for deeper investigation, specifically affecting attempts to gather aggregated IP/port data for CVE-2025-55182 (END-001).
- **custom_basic_search**:
    - **Failure reason**: Did not correctly filter by `type_filter=Adbhoney`, returning general top source IPs instead of specific ADBHoney-related IPs.
    - **Affected validations**: Hindered the ability to get specific source IPs for ADBHoney events (BCM-001).

These issues led to the `Partial` completion status and reduced confidence in some specific correlations, requiring the `provisional` label for some findings.

13) Agent Action Summary (Audit Trail)
- **ParallelInvestigationAgent** (and its sub-agents: BaselineAgent, KnownSignalAgent, CredentialNoiseAgent, HoneypotSpecificAgent)
    - **Purpose**: Conduct initial broad data collection across various telemetry sources.
    - **Inputs used**: Investigation timeframe.
    - **Actions taken**: Queried for total attacks, top countries/IPs/ASNs, alert signatures/CVEs/categories, top usernames/passwords, p0f OS distribution, and honeypot-specific data (Redis, ADBHoney, Conpot, Tanner).
    - **Key results**: Identified total attacks (19643), top attacking countries (US, Ukraine, HK), top source ASNs (DigitalOcean, Dynu, Google LLC), prevalence of VNC scanning (16516), CVE-2025-55182 hits (119), common credential noise, ADBHoney malware downloads (3 unique, 6 total), Tanner path traversal/sensitive file access.
    - **Errors or gaps**: None reported by the individual parallel agents themselves, but their outputs fed into subsequent agents where issues were identified.

- **CandidateDiscoveryAgent**
    - **Purpose**: Identify potential high-signal activities and unusual patterns.
    - **Inputs used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    - **Actions taken**: Performed various `kibanna_discover_query`, `suricata_lenient_phrase_search`, `two_level_terms_aggregated`, `top_src_ips_for_cve`, `discover_by_keyword`, and `custom_basic_search` operations to pinpoint candidates.
    - **Key results**: Identified candidates for emerging n-day exploitation (CVE-2025-55182), botnet/campaign mapping (ADBHoney malware), and novel exploit candidates (Tanner path traversal/sensitive file access). Generated a triage summary.
    - **Errors or gaps**: `kibanna_discover_query` (multiple instances), `top_src_ips_for_cve`, `two_level_terms_aggregated` (multiple instances), and `complete_custom_search` all failed due to various Elasticsearch errors (e.g., 'Expected text at 1:71 but found START_ARRAY', 'Returned 0 results'). This led to `degraded_mode=true` and blocked several validation steps.

- **CandidateValidationLoopAgent**
    - **Purpose**: Orchestrate the validation of discovered candidates.
    - **Inputs used**: Candidates from `CandidateDiscoveryAgent`'s output.
    - **Actions taken**: Iterated through 3 candidates (END-001, BCM-001, NEC-001). For each, it loaded the candidate, called `CandidateValidationAgent`, and stored the result via `CandidateLoopReducerAgent`.
    - **Key results**: Successfully processed all 3 candidates.
    - **Errors or gaps**: Loop exited successfully as requested after all candidates were processed.

- **CandidateValidationAgent**
    - **Purpose**: Perform detailed validation and enrichment for individual candidates.
    - **Inputs used**: Individual candidate details from `CandidateLoopControllerAgent`.
    - **Actions taken**: For END-001, queried for CVE events and events for a specific source IP. For BCM-001, queried for ADBHoney events, two-level aggregations on IP-to-filename, and keyword searches. For NEC-001, queried for specific web path samples.
    - **Key results**:
        - END-001: Correlated CVE-2025-55182 with source IP and general HTTP activity.
        - BCM-001: Confirmed malware samples and associated source IPs for ADBHoney.
        - NEC-001: Confirmed path traversal and sensitive file access attempts with associated Suricata signatures and source IPs.
    - **Errors or gaps**: `kibanna_discover_query` failed for END-001 and BCM-001. `two_level_terms_aggregated` failed for BCM-001. `custom_basic_search` failed for BCM-001. This resulted in `evidence_gaps` and `blocked_validation_steps` for detailed correlations.

- **OSINTAgent**
    - **Purpose**: Gather external threat intelligence to validate knownness and novelty.
    - **Inputs used**: Key indicators and descriptions from validated candidates (CVE ID, malware hash, Suricata signatures, exploitation types).
    - **Actions taken**: Performed web searches for CVE-2025-55182, a specific malware hash, and descriptions of path traversal and sensitive file disclosure techniques (e.g., "/etc/passwd", ".env", "api/backup", "client_secret.json").
    - **Key results**:
        - Confirmed CVE-2025-55182 as a critical, actively exploited RCE (reduces novelty for END-001).
        - Malware hash search was inconclusive, no specific public mapping found (inconclusive for BCM-001).
        - Confirmed path traversal and sensitive file access techniques are well-known, signature-mapped scanning activities (significantly reduces novelty for NEC-001, leading to reclassification).
    - **Errors or gaps**: None reported by the OSINT tool itself; results reflect available public information.

- **ReportAgent** (self)
    - **Purpose**: Compile the final report from workflow state outputs.
    - **Inputs used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates`, `osint_validation_result`.
    - **Actions taken**: Consolidated all provided JSON outputs, applied mandatory logic for classification and status, formatted into the strict markdown report structure.
    - **Key results**: Generated the complete investigation report.
    - **Errors or gaps**: None; successfully compiled report using available data.

- **SaveReportAgent**
    - **Purpose**: Save the generated report to a persistent store.
    - **Inputs used**: The markdown report content from ReportAgent.
    - **Actions taken**: `default_write_file` (implied downstream call).
    - **Key results**: (Downstream call)
    - **Errors or gaps**: (Downstream call)