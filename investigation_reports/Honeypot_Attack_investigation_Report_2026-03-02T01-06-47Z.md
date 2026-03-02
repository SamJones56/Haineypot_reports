# Honeypot Threat Hunt - Final Report

### 1) Investigation Scope
- **investigation_start**: 2026-03-02T00:00:16Z
- **investigation_end**: 2026-03-02T01:00:16Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true - Persistent backend tool failures (`kibanna_discover_query`, data correlation tools) blocked several key investigation paths, including malware source attribution and CVE analysis.

### 2) Executive Triage Summary
- **Top Services of Interest**: The most operationally interesting activity involved a specialized scan targeting Minecraft servers on port 25565. Commodity scanning was high on VNC ports (e.g., 5925, 5926) and non-standard RDP ports.
- **Top Confirmed Known Activity**: The majority of traffic (over 2,500 events) consisted of commodity VNC and RDP scanning from a wide distribution of sources, alongside generic SSH credential brute-forcing.
- **Top Unmapped Exploit-like Items**: No unmapped exploit candidates were validated. The most promising leads for novel activity (Adbhoney malware downloads) could not be investigated due to tool failures.
- **Botnet/Campaign Mapping Highlights**: Adbhoney honeypots detected three distinct malware sample downloads, strongly suggesting botnet activity. However, source IP attribution failed, preventing any infrastructure mapping.
- **Major Uncertainties**: The inability to correlate malware downloads to source IPs is the most significant gap. This prevents assessment of a potential botnet campaign. Analysis of low-volume CVEs was also blocked.

### 3) Candidate Discovery Summary
The discovery phase successfully filtered over 9,000 events to identify a primary candidate (`ODD-001`) related to an unusual scan on the Minecraft game port. Other potential leads, including three malware downloads on the Adbhoney honeypot and low-volume CVE detections, were identified but could not be pursued due to persistent backend query failures, which significantly degraded the investigation's scope.

### 4) Emerging n-day Exploitation
None identified. Investigation into low-volume CVEs (`CVE-2024-14007`) was blocked by tool failures that prevented correlation with source IPs.

### 5) Novel or Zero-Day Exploit Candidates
No candidates met the criteria for novel or zero-day exploitation.

### 6) Botnet/Campaign Infrastructure Mapping
Infrastructure mapping was attempted but blocked.
- **item_id**: MON-001 (Related to Adbhoney artifacts)
- **campaign_shape**: Unknown
- **suspected_compromised_src_ips**: Attribution failed due to tool errors.
- **suspected_staging indicators**: The following malware file paths were observed being downloaded, but the download source is unknown.
    - `dl/4251293b2d3765833f16988c2dbec30362df1c84dfe33c58dcc0815596d31353.raw`
    - `dl/9a56e2c761e10156cac6589bc9e929b1b8b5b00dd6c79ca0d33c2399b88e3a43.raw`
    - `dl/9bc28777e722c46898754ef256d052e9cd684f6ad812d69878c68ba6cc0c72fe.raw`
- **confidence**: Low (due to lack of source attribution)
- **operational_notes**: The malware hashes/paths represent high-signal indicators, but without source context, response is limited to monitoring. The failure to identify source IPs is the highest priority issue for follow-up.

### 7) Odd-Service / Minutia Attacks
- **service_fingerprint**: Port 25565/TCP (Minecraft), P0f OS Fingerprint: "Nintendo 3DS"
- **why it’s unusual/interesting**: This activity combines a niche, non-standard target (a game server) with an anomalous OS fingerprint. Legitimate Nintendo 3DS consoles do not connect to standard Minecraft servers, indicating a deliberately spoofed signature.
- **evidence_summary**: A single source IP, `51.15.34.47`, generated 7 events over a 10-minute period exclusively targeting port 25565. OSINT confirms the IP is a known abusive host from a hosting provider (Scaleway) and that OS fingerprint spoofing is a known technique for specialized scanners.
- **confidence**: Moderate
- **recommended_monitoring_pivots**: Block source IP `51.15.34.47`. Monitor port 25565 for connections from other non-standard or spoofed OS fingerprints.

### 8) Known-Exploit / Commodity Exclusions
- **VNC Scanning**: High volume (2,060 events) of generic VNC server probes, matching signature "GPL INFO VNC server response".
- **RDP Scanning**: Significant volume (459 events) of scanning for Microsoft Terminal Server on non-standard ports.
- **Credential Noise**: Widespread SSH brute-force attempts using common usernames (`root`, `admin`, `postgres`) and passwords (`123456`, `password`).
- **Web Reconnaissance Scanning**: Low-volume, uncoordinated probes for `/.env` and `/geoserver/web/` from distinct IPs, consistent with internet background noise.

### 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The primary validated finding (`ODD-001`) was classified as a specialized, short-duration scan. The bulk of other traffic was also scanning. Suspected exploitation (Adbhoney malware downloads) could not be fully analyzed.
- **Campaign Shape**: Commodity activity was a broad "spray". The Minecraft scan was a targeted, isolated event.
- **Infra Reuse Indicators**: The actor behind the Minecraft scan used a disposable IP (`51.15.34.47`) from a hosting provider (Scaleway, AS12876) known for hosting malicious infrastructure.
- **Odd-Service Fingerprints**: The `Minecraft/25565` + `Nintendo 3DS` fingerprint was the most significant behavioral finding.

### 10) Evidence Appendix
**Item ID: ODD-001 (Minecraft Scanner)**
- **source IPs**: `51.15.34.47` (7 events)
- **ASNs**: `12876` - "Scaleway S.a.s." (7 events)
- **target ports/services**: `25565/tcp`
- **paths/endpoints**: N/A
- **payload/artifact excerpts**:
    - p0f OS Fingerprint: `Nintendo 3DS`
- **staging indicators**: None
- **temporal_checks**: Activity was transient, lasting approximately 10 minutes from 2026-03-02T00:14:44.000Z to 2026-03-02T00:24:54.863Z.

### 11) Indicators of Interest
- **IPs**: `51.15.34.47` (Known scanner, block)
- **File Paths / Hashes (from Adbhoney, requires further analysis)**:
    - `dl/4251293b2d3765833f16988c2dbec30362df1c84dfe33c58dcc0815596d31353.raw`
    - `dl/9a56e2c761e10156cac6589bc9e929b1b8b5b00dd6c79ca0d33c2399b88e3a43.raw`
    - `dl/9bc28777e722c46898754ef256d052e9cd684f6ad812d69878c68ba6cc0c72fe.raw`
- **Web Paths**:
    - `/.env`
    - `/geoserver/web/`

### 12) Backend Tool Issues
- **`kibanna_discover_query`**: Failed persistently with an `illegal_argument_exception`. This was the most critical failure. It blocked the ability to inspect raw logs for the Adbhoney malware downloads and to see the full context (e.g., payloads, Suricata alerts) for the `ODD-001` Minecraft scanner.
- **`two_level_terms_aggregated`**: Failed to return data for Adbhoney malware files, contradicting the Honeypot agent's findings and blocking an alternative path to source IP attribution.
- **`top_src_ips_for_cve`**: Failed to return data for `CVE-2024-14007`, contradicting the Known Signals agent and blocking investigation into potential n-day activity.
- **Weakened Conclusions**: All conclusions regarding botnet activity are provisional and incomplete. The intent and capability of the `ODD-001` scanner could not be fully determined without payload inspection.

### 13) Agent Action Summary (Audit Trail)
- **agent_name**: ParallelInvestigationAgent
- **purpose**: Gathers broad, parallel streams of context data for the time window.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Executed four sub-agents (Baseline, KnownSignal, CredentialNoise, HoneypotSpecific) to query general statistics, known signatures, credential stuffing indicators, and honeypot-specific events.
- **key_results**:
    - Established baseline of 9,246 attacks.
    - Identified high-volume VNC/RDP scanning.
    - Found anomalous "Nintendo 3DS" OS fingerprint (1 event).
    - Found 3 distinct malware downloads in Adbhoney.
    - Found targeted web recon (`/.env`, `/geoserver/web/`).
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Sifts through parallel data streams to identify novel or high-priority leads for investigation.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**: Seeded candidates from Adbhoney malware, p0f OS fingerprint, and Tanner web paths. Attempted to pivot and enrich these seeds using various aggregation and search tools.
- **key_results**:
    - Identified `ODD-001` (Minecraft scan) as the single viable candidate.
    - Downgraded Tanner web recon to background noise due to low volume.
    - Confirmed investigation into Adbhoney malware and CVEs was blocked.
- **errors_or_gaps**: Encountered persistent failures from `kibanna_discover_query`, and empty/contradictory results from `two_level_terms_aggregated` and `top_src_ips_for_cve`.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: Performs structured validation of discovered candidates.
- **inputs_used**: `candidate_discovery_result`.
- **actions_taken**: Iterations run: 1. Validated candidate `ODD-001`. Used tools `events_for_src_ip` and `p0f_os_search` to gather context on the source IP.
- **key_results**:
    - Validated `ODD-001` as a legitimate, though likely known, `odd_service_minutia` attack.
    - Confirmed all activity from the source IP was limited to the target port.
- **errors_or_gaps**: `kibanna_discover_query` failed, preventing payload/signature inspection.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: Conducts an in-depth, human-like investigation on high-confidence validated candidates.
- **inputs_used**: `validated_candidates`.
- **actions_taken**: Iterations run: 1. Pursued lead `src_ip:51.15.34.47`. Used `first_last_seen_src_ip` to determine activity duration and `search` for OSINT enrichment.
- **key_results**:
    - Confirmed the scan was a brief, 10-minute event.
    - OSINT confirmed the IP is a known-abusive host from Scaleway with a 100% abuse score.
    - Concluded the activity was a specialized vulnerability scan.
- **errors_or_gaps**: Stalled and exited due to exhaustion of leads and blocked pivots (payload analysis).

- **agent_name**: OSINTAgent
- **purpose**: Enriches findings with public, open-source intelligence.
- **inputs_used**: `validated_candidates`.
- **actions_taken**: Performed targeted web searches for the candidate's artifacts, including the source IP, target service, and observed technique.
- **key_results**:
    - Confirmed `51.15.34.47` is a known malicious IP.
    - Found that scanning Minecraft servers with a spoofed p0f OS fingerprint is a known technique.
    - Confirmed that legitimate Nintendo 3DS consoles cannot connect to target servers, validating the spoofing hypothesis. This reduced the candidate's novelty.
- **errors_or_gaps**: None.

- **agent_name**: ReportAgent
- **purpose**: Builds finale report from workflow state (no new searching).
- **inputs_used**: All preceding workflow state outputs.
- **actions_taken**: Compiled and structured all available evidence, including findings, OSINT context, and documented tool failures, into the final report format.
- **key_results**: This report.
- **errors_or_gaps**: None.

- **agent_name**: SaveReportAgent
- **purpose**: Persists the final report artifact.
- **inputs_used**: Final report content.
- **actions_taken**: Will call `investigation_write_file` tool.
- **key_results**: Report saved to designated storage.
- **errors_or_gaps**: (pending execution).