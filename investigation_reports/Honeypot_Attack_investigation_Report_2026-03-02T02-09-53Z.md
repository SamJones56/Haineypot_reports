# Honeypot Threat Hunting Final Report

### 1) Investigation Scope
-   **investigation_start**: `2026-03-02T01:00:20Z`
-   **investigation_end**: `2026-03-02T02:00:20Z`
-   **completion_status**: Partial (degraded evidence)
-   **degraded_mode**: true. Multiple data retrieval tools (`kibanna_discover_query`, `top_src_ips_for_cve`) failed during the investigation, preventing the correlation of several key events (malware downloads, ICS activity, one CVE) with their source IPs.

### 2) Executive Triage Summary
-   **Top Services of Interest**: Significant activity was observed against SMB (`445/tcp`), VNC (`59xx/tcp`), SSH (`22/tcp`), and Apache ActiveMQ (`61616/tcp`).
-   **Odd-Service Minutia**: Low-volume but noteworthy interactions were detected with the `kamstrup_management_protocol`, a proprietary Industrial Control System (ICS) protocol, indicating potential specialized reconnaissance.
-   **Top Confirmed Known Exploitation**: Confirmed exploitation of **CVE-2023-46604** (Apache ActiveMQ RCE) from source IP `193.26.115.178`. OSINT links this IP to the AsyncRAT malware family.
-   **Top Unmapped Exploit-Like Items**: Three distinct malware samples were downloaded to the Adbhoney honeypot. OSINT checks against their hashes yielded no public results, suggesting they may be part of a new or private campaign. This finding is provisional due to an inability to retrieve the downloader's IP.
-   **Botnet/Campaign Mapping Highlights**: A high-volume SMB scanning campaign was identified, originating from a single IP (`180.165.27.87`) in China (AS4812, China Telecom) responsible for over 1,900 events.
-   **Major Uncertainties**: Source IPs for the malware download campaign, the ICS protocol probing, and alerts for `CVE-2024-14007` could not be determined due to persistent tool failures. These findings require manual follow-up.

### 3) Candidate Discovery Summary
-   The discovery phase analyzed 11,302 total attacks, identifying several key areas for investigation.
-   Initial seeds included high-volume VNC and SMB scanning, SSH brute-force noise, specific alerts for CVE-2023-46604 and CVE-2024-14007, malware downloads on the Adbhoney honeypot, and rare ICS protocol events on the Conpot honeypot.
-   Discovery was materially affected by tool errors (`kibanna_discover_query`, `top_src_ips_for_cve`), which prevented the agent from fully enriching candidates with source IPs, leading to several provisional findings.

### 4) Emerging n-day Exploitation
**Item 1: Apache ActiveMQ RCE**
-   **cve/signature mapping**: CVE-2023-46604 / `ET EXPLOIT Apache ActiveMQ Remote Code Execution Attempt (CVE-2023-46604)`
-   **evidence summary**: 2 exploit attempts detected from a single source IP. The IP was also flagged by the `Spamhaus DROP` list.
-   **affected service/port**: `61616/tcp` (Apache ActiveMQ)
-   **confidence**: High
-   **operational notes**: Source IP `193.26.115.178` is linked via OSINT to the AsyncRAT malware family, indicating this exploit is likely used as an initial access vector for malware delivery.

**Item 2: TVT NVR Authentication Bypass (Provisional)**
-   **cve/signature mapping**: CVE-2024-14007
-   **evidence summary**: 2 Suricata alerts were generated.
-   **affected service/port**: Unknown
-   **confidence**: Moderate
-   **operational notes**: This finding is **Provisional**. Tool failures prevented the retrieval of the source IP and destination port, blocking full validation and OSINT cross-referencing. OSINT confirms this is a known auth bypass in TVT DVR/NVR firmware.

### 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
*No candidates met the criteria for this category in the current investigation window.*

### 6) Botnet/Campaign Infrastructure Mapping
**Item 1: Adbhoney Malware Dropper Campaign (Provisional)**
-   **item_id**: `BCM-ADBHONEY-DROPPER-1`
-   **campaign_shape**: unknown
-   **suspected_compromised_src_ips**: `unknown` (tool failure)
-   **ASNs / geo hints**: unavailable
-   **suspected_staging indicators**: Three malware samples were downloaded, identified by SHA256 hashes:
    -   `4251293b2d3765833f16988c2dbec30362df1c84dfe33c58dcc0815596d31353`
    -   `9a56e2c761e10156cac6589bc9e929b1b8b5b00dd6c79ca0d33c2399b88e3a43`
    -   `9bc28777e722c46898754ef256d052e9cd684f6ad812d69878c68ba6cc0c72fe`
-   **suspected_c2 indicators**: None observed.
-   **confidence**: Moderate
-   **operational notes**: This is a **Provisional** finding. The inability to retrieve the source IP severely limits impact assessment. However, OSINT searches for the malware hashes returned no public results, which increases concern that this may be a new or non-public campaign. Manual review of Adbhoney logs is required.

**Item 2: High-Volume SMB Scanning Node**
-   **item_id**: `BCM-SMB-SCAN-1`
-   **campaign_shape**: fan-in (one source, many targets)
-   **suspected_compromised_src_ips**: `180.165.27.87` (1,934 events)
-   **ASNs / geo hints**: ASN 4812 / China Telecom Group
-   **suspected_staging indicators**: None observed.
-   **suspected_c2 indicators**: None observed.
-   **confidence**: High
-   **operational notes**: Commodity but high-volume scanning activity focused on a single service from a single host. Indicates a dedicated scanner, likely searching for common SMB vulnerabilities (e.g., EternalBlue).

### 7) Odd-Service / Minutia Attacks
**Item 1: ICS Protocol Probing (Provisional)**
-   **service_fingerprint**: `kamstrup_management_protocol` (Conpot ICS Honeypot)
-   **why it’s unusual/interesting**: This is a proprietary protocol for smart meters (ICS/OT). Its appearance in general internet scanning is highly anomalous and suggests targeted reconnaissance by a specialized actor.
-   **evidence summary**: 2 interaction events were logged.
-   **confidence**: Medium
-   **recommended monitoring pivots**: This is a **Provisional** finding. Manual review of Conpot logs is required to identify the source IP. Monitor for any further interaction with ICS/OT ports or protocols.

### 8) Known-Exploit / Commodity Exclusions
-   **Credential Noise**: Widespread SSH/Telnet brute-force attempts using common usernames (`root`, `admin`, `ubuntu`) and passwords (`123456`, `password`, `qwerty`). Classified as background noise.
-   **VNC Scanning**: High volume (2,000+ events) of VNC scanning identified by the `GPL INFO VNC server response` signature across many source IPs.
-   **RDP Scanning**: Scanning for Microsoft Terminal Server on non-standard ports was observed, matching the `ET SCAN MS Terminal Server Traffic on Non-standard Port` signature.
-   **SSH Scanning**: Activity related to SSH clients built with Go (`ET INFO SSH-2.0-Go`) and standard SSH sessions was prevalent.

### 9) Infrastructure & Behavioral Classification
-   **CVE-2023-46604 Activity**: Classified as **Exploitation**. The campaign shape appears to be **Fan-out** from a single-use IP (`193.26.115.178`) within ASN 210558.
-   **SMB Activity**: Classified as **Scanning**. The campaign shape is **Fan-in**, with a single IP (`180.165.27.87`) from ASN 4812 being the sole source.
-   **Adbhoney Malware**: Classified as **Exploitation (Payload Delivery)**. The campaign shape and infrastructure reuse are unknown due to missing data.
-   **Conpot ICS Activity**: Classified as **Scanning/Reconnaissance**. The infrastructure is unknown. The key fingerprint is **Odd-Service (ICS/OT Protocol)**.

### 10) Evidence Appendix
**Item: CVE-2023-46604 Exploitation** (`CVE-2023-46604-2026-03-02T01:05:18.044Z`)
-   **source IPs**: `193.26.115.178` (2 events)
-   **ASNs**: `210558` (1337 Services GmbH)
-   **target ports/services**: `61616/tcp`
-   **payload/artifact excerpts**: Suricata Signature: `ET EXPLOIT Apache ActiveMQ Remote Code Execution Attempt (CVE-2023-46604)`
-   **temporal checks results**: First seen `2026-03-02T01:05:17.000Z`, Last seen `2026-03-02T01:06:27.780Z`.

**Item: High-Volume SMB Scanning** (`BCM-SMB-SCAN-1`)
-   **source IPs**: `180.165.27.87` (1,934 events)
-   **ASNs**: `4812` (China Telecom Group)
-   **target ports/services**: `445/tcp`
-   **payload/artifact excerpts**: Connection attempts only.
-   **temporal checks results**: unavailable

**Item: Adbhoney Malware Dropper** (`BCM-ADBHONEY-DROPPER-1`)
-   **source IPs**: `unknown`
-   **target ports/services**: Adbhoney service port
-   **staging indicators**:
    -   `dl/4251293b2d3765833f16988c2dbec30362df1c84dfe33c58dcc0815596d31353.raw`
    -   `dl/9a56e2c761e10156cac6589bc9e929b1b8b5b00dd6c79ca0d33c2399b88e3a43.raw`
    -   `dl/9bc28777e722c46898754ef256d052e9cd684f6ad812d69878c68ba6cc0c72fe.raw`
-   **temporal checks results**: unavailable

### 11) Indicators of Interest
-   **IP Addresses**:
    -   `193.26.115.178` (Confirmed source of CVE-2023-46604 exploit; linked to AsyncRAT)
    -   `180.165.27.87` (High-volume SMB scanner)
-   **SHA256 Hashes** (Unknown Malware):
    -   `4251293b2d3765833f16988c2dbec30362df1c84dfe33c58dcc0815596d31353`
    -   `9a56e2c761e10156cac6589bc9e929b1b8b5b00dd6c79ca0d33c2399b88e3a43`
    -   `9bc28777e722c46898754ef256d052e9cd684f6ad812d69878c68ba6cc0c72fe`
-   **Signatures / Artifacts**:
    -   `ET EXPLOIT Apache ActiveMQ Remote Code Execution Attempt (CVE-2023-46604)`
    -   Interaction with `kamstrup_management_protocol`

### 12) Backend Tool Issues
-   **kibanna_discover_query**: This tool failed repeatedly with a `status 400` error (`illegal_argument_exception`). This was the primary cause of degradation, blocking source IP lookups for Adbhoney malware downloads and Conpot ICS activity.
-   **top_src_ips_for_cve**: The tool returned zero results for both CVEs during the discovery phase, failing to provide an initial link between alerts and attackers.
-   **match_query**: This tool also failed with a `status 400` error during the deep investigation phase, preventing pivots on suspected C2 ports.
-   **Weakened Conclusions**: The findings for the **Adbhoney Malware Campaign**, **ICS Protocol Probing**, and **CVE-2024-14007** are marked as **Provisional** because the source IPs could not be identified. This prevents a full assessment of the threat actor's infrastructure and campaign scope.

### 13) Agent Action Summary (Audit Trail)
-   **agent_name**: ParallelInvestigationAgent
-   **purpose**: Gathers broad, parallel data streams for initial context.
-   **inputs_used**: `investigation_start`, `investigation_end`.
-   **actions_taken**: Executed four sub-agents (Baseline, KnownSignal, CredentialNoise, HoneypotSpecific) to query general stats, alerts, and honeypot logs.
-   **key_results**: Identified 11,302 attacks, top source countries, high-volume scanning (VNC, SMB), CVE alerts (CVE-2023-46604, CVE-2024-14007), commodity credential stuffing, Adbhoney malware downloads, and Conpot ICS protocol events.
-   **errors_or_gaps**: None.

-   **agent_name**: CandidateDiscoveryAgent
-   **purpose**: Merges parallel data streams and identifies initial leads for validation.
-   **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
-   **actions_taken**: Merged inputs and attempted to enrich seeds using `top_src_ips_for_cve` and `kibanna_discover_query`.
-   **key_results**: Generated 5 candidates for further analysis, flagging n-day exploits, botnet activity, and odd-service behavior.
-   **errors_or_gaps**: Multiple tool failures (`kibanna_discover_query`, `top_src_ips_for_cve`) resulted in a `degraded_mode` status, with several candidates lacking source IPs.

-   **agent_name**: CandidateValidationLoopAgent
-   **purpose**: Iterates through candidates, performs targeted validation, and produces structured findings.
-   **inputs_used**: `candidate_discovery_result`.
-   **actions_taken**: Ran for 1 iteration on the first queued candidate (CVE-2023-46604). Used `suricata_cve_samples` and `events_for_src_ip` to validate.
-   **key_results**: Successfully validated the CVE-2023-46604 exploit, identifying source IP `193.26.115.178`.
-   **errors_or_gaps**: The loop only processed 1 of 5 candidates before passing control. The remaining 4 candidates were not put through this validation stage and retain their provisional status from discovery.

-   **agent_name**: DeepInvestigationLoopController
-   **purpose**: Conducts deep-dive investigation on a high-confidence, validated lead.
-   **inputs_used**: Validated finding for `CVE-2023-46604`.
-   **actions_taken**: Ran for 3 iterations, pursuing lead `src_ip:193.26.115.178`. Used `first_last_seen_src_ip`, `search` (OSINT), and attempted pivots with `kibanna_discover_query`, `match_query`, `complete_custom_search`.
-   **key_results**: OSINT confirmed the attacker IP's association with AsyncRAT. Internal queries showed it was the only active IP from its ASN in the window.
-   **errors_or_gaps**: Exited the loop due to repeated tool failures (`kibanna_discover_query`, `match_query`) which stalled investigative pivots into related infrastructure.

-   **agent_name**: OSINTAgent
-   **purpose**: Enriches findings with external intelligence.
-   **inputs_used**: All provisional and validated candidates.
-   **actions_taken**: Executed `search` queries for CVEs, malware hashes, and key indicators.
-   **key_results**: Confirmed public details for both CVEs. Critically, found **no public information** for the three malware hashes, increasing their significance.
-   **errors_or_gaps**: None.

-   **agent_name**: ReportAgent
-   **purpose**: Builds finale report from workflow state (no new searching).
-   **inputs_used**: All preceding workflow state outputs.
-   **actions_taken**: Compiled this final markdown report.
-   **key_results**: The report content.
-   **errors_or_gaps**: None.

-   **agent_name**: SaveReportAgent
-   **purpose**: Persists the final report artifact.
-   **inputs_used**: This markdown report.
-   **actions_taken**: Will call the file write tool.
-   **key_results**: Report saved (pending action).
-   **errors_or_gaps**: None.
