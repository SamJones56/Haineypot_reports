# Honeypot Threat Hunting Final Report

### 1) Investigation Scope
- **investigation_start**: 2026-03-02T02:00:19Z
- **investigation_end**: 2026-03-02T03:01:41Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true - Key correlation queries failed, preventing the definitive association of source IPs with specific Suricata alerts (DoublePulsar, CVEs) and odd-service protocol activity (Kamstrup).

### 2) Executive Triage Summary
- **Top Services/Ports of Interest**: 
    - **HTTP (80/tcp)**: Targeted by a multi-exploit scanner attempting PHPUnit RCE, PHP LFI/RCE, and CGI-bin command injection.
    - **SMB (445/tcp)**: High-volume activity from a single Chinese ASN, circumstantially linked to DoublePulsar exploit signatures.
    - **ICS/OT (kamstrup_protocol)**: Unusual and unsolicited interactions with an Industrial Control System protocol for smart utility meters were observed.
    - **SSH (22/tcp)**: Standard, high-volume commodity brute-force attacks.
    - **VNC-like (5925/tcp, 5926/tcp)**: Widespread scanning for VNC services on non-standard ports.
- **Top Confirmed Known Exploitation**:
    - Widespread scanning consistent with **DoublePulsar (related to EternalBlue/MS17-010)** was detected via signatures.
    - Alerts for **CVE-2023-46604 (Apache ActiveMQ RCE)** indicate targeting of a recently disclosed and actively exploited vulnerability.
    - A web scanning campaign utilized an exploit for **CVE-2017-9841 (PHPUnit RCE)**.
- **Unmapped Exploit-like Items**: No novel or zero-day candidates were validated. All exploit-like behavior was mapped to known vulnerabilities or scanners.
- **Botnet/Campaign Mapping Highlights**:
    - Identified a specific web scanner (`94.191.45.228`) systematically attempting at least three distinct vulnerability types.
    - Provisionally mapped a high-volume SMB campaign (`180.165.27.87` from China Telecom) to DoublePulsar activity.
- **Major Uncertainties**: The source IPs for the DoublePulsar alerts, CVE-2023-46604 alerts, and the Kamstrup ICS protocol activity could not be determined due to backend query failures, limiting attribution.

### 3) Candidate Discovery Summary
- The discovery phase successfully merged baseline, known signal, credential noise, and honeypot-specific telemetry.
- **Key candidates identified**: A multi-exploit web campaign (`BCM-1`), a suspected SMB exploit campaign (`BCM-2`), and anomalous ICS protocol activity (`ODD-1`).
- **Material Issues**: Discovery was impacted by the failure of several correlation queries (`kibanna_discover_query`, `suricata_lenient_phrase_search`, `two_level_terms_aggregated`), which prevented direct evidence links for several key findings.

### 4) Emerging n-day Exploitation
- **CVE/Signature Mapping**: CVE-2023-46604 (Apache ActiveMQ RCE)
- **Evidence Summary**: Low-volume alerts (2 events) for this CVE were detected in the time window. OSINT confirms this CVE is under widespread, active exploitation by multiple threat actors for deploying ransomware, miners, and botnets. Source IPs could not be identified due to query failures.
- **Affected Service/Port**: ActiveMQ (default 61616/tcp, but not specified in telemetry)
- **Confidence**: Moderate (Alert is present, but source is unconfirmed)
- **Operational Notes**: Monitor for any increase in activity related to this CVE. The lack of source IP data prevents immediate blocking.

### 5) Novel or Zero-Day Exploit Candidates
No novel or zero-day exploit candidates were validated in this window. All observed exploit-like behavior was mapped to known vulnerabilities or commodity scanners.

### 6) Botnet/Campaign Infrastructure Mapping
- **item_id**: BCM-1
- **campaign_shape**: fan-out (scanning)
- **suspected_compromised_src_ips**: `94.191.45.228` (1)
- **ASNs / geo hints**: Tencent Cloud Computing (Beijing) Co., Ltd. (per OSINT)
- **suspected_staging indicators**: N/A (direct exploitation attempts)
- **suspected_c2 indicators**: None observed.
- **confidence**: High
- **operational notes**: This IP is a known malicious scanner. Block and monitor for other IPs exhibiting this multi-exploit pattern. The activity is consistent with known scanner tooling rather than a novel campaign.

---
- **item_id**: BCM-2 (Provisional)
- **campaign_shape**: fan-out (scanning/exploitation)
- **suspected_compromised_src_ips**: `180.165.27.87` (1443 events)
- **ASNs / geo hints**: AS4812 (China Telecom Group)
- **suspected_staging indicators**: N/A
- **suspected_c2 indicators**: None observed.
- **confidence**: Medium
- **operational notes**: The link between this high-volume SMB traffic and the observed DoublePulsar alerts is circumstantial due to query failures. OSINT found no public link. Monitor this IP for continued SMB activity.

### 7) Odd-Service / Minutia Attacks
- **item_id**: ODD-1 (Provisional)
- **service_fingerprint**: `kamstrup_protocol` (ICS/OT Smart Meter Protocol) via Conpot honeypot.
- **why it’s unusual/interesting**: This is a proprietary protocol for utility smart meters. Unsolicited remote network interaction is highly anomalous and not consistent with publicly documented scanning campaigns or legitimate use, which often requires physical access.
- **evidence summary**: 10 events recorded by the Conpot honeypot. Source IP could not be identified due to query failure.
- **confidence**: Low (due to lack of source attribution)
- **recommended monitoring pivots**: Focus on restoring data correlation for the Conpot honeypot to enable source IP identification for this and future events.

### 8) Known-Exploit / Commodity Exclusions
- **Credential Noise**: Widespread SSH brute-force attempts using common usernames (`root`, `admin`, `user`) and passwords (`123456`, `password`).
- **Commodity Scanning**:
    - High-volume VNC scanning activity, confirmed by `GPL INFO VNC server response` signatures (2,029 events), targeting standard and non-standard ports.
    - General network noise and malformed packets identified by `SURICATA IPv4 truncated packet` and related signatures.
- **Known Bot Patterns**:
    - Attempts to exploit **CVE-2017-9841 (PHPUnit RCE)** were identified as part of the broader `BCM-1` scanner activity.
    - A significant number of **DoublePulsar Backdoor** signatures (464 events) indicate continued exploitation of the MS17-010 vulnerability family.

### 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The window contained both broad scanning (VNC, SSH) and targeted exploitation attempts (PHPUnit RCE, PHP LFI, CGI injection, suspected DoublePulsar, suspected ActiveMQ RCE).
- **Campaign Shape**: All observed campaigns exhibited a `fan-out` shape, consistent with widespread scanning and exploitation from a small number of sources to many targets.
- **Infra Reuse Indicators**: The source IP `94.191.45.228` was observed using at least three distinct web exploit techniques, indicating reuse of infrastructure for multiple attack types.
- **Odd-Service Fingerprints**: Activity involving `kamstrup_protocol` represents probing of ICS/OT-related services.

### 10) Evidence Appendix
- **Item**: BCM-1 (Multi-Exploit Web Scanner)
    - **source IPs**: `94.191.45.228`
    - **ASNs**: Tencent Cloud (per OSINT)
    - **target ports/services**: 80/tcp (HTTP)
    - **paths/endpoints**:
        - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
        - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
        - `/admin/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
        - `/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh`
    - **temporal checks**: N/A for this window.

- **Item**: BCM-2 (Suspected DoublePulsar Campaign)
    - **source IPs**: `180.165.27.87`
    - **ASNs**: 4812 (China Telecom Group)
    - **target ports/services**: 445/tcp (SMB)
    - **payload/artifact excerpts**: Signature: `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`
    - **temporal checks**: N/A for this window.

- **Item**: ODD-1 (ICS Protocol Probing)
    - **source IPs**: Unavailable
    - **ASNs**: Unavailable
    - **target ports/services**: Unknown port, `kamstrup_protocol`
    - **payload/artifact excerpts**: N/A
    - **temporal checks**: N/A for this window.

- **Item**: Emerging n-day (ActiveMQ)
    - **source IPs**: Unavailable
    - **ASNs**: Unavailable
    - **target ports/services**: Unknown port, ActiveMQ service
    - **payload/artifact excerpts**: Signature alert for `CVE-2023-46604`
    - **temporal checks**: N/A for this window.

### 11) Indicators of Interest
- **IPs**:
    - `94.191.45.228` (Known multi-exploit web scanner)
    - `180.165.27.87` (High-volume SMB activity, suspected DoublePulsar)
- **URLs/Paths**:
    - `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (Indicator for CVE-2017-9841)
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` (Indicator for PHP LFI/RCE)
- **Signatures / CVEs**:
    - `CVE-2023-46604`
    - `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`
    - `kamstrup_protocol` (Anomalous protocol)

### 12) Backend Tool Issues
- **`kibanna_discover_query`**: Failed when searching for a URL path containing special characters. This blocked direct inspection of the PHP LFI/RCE payload.
- **`suricata_lenient_phrase_search`**: Failed to return results for the phrase "DoublePulsar". This blocked the primary validation step for linking `180.165.27.87` to the exploit alerts.
- **`top_src_ips_for_cve`**: Failed to return any source IPs for `CVE-2023-46604`. This prevented attribution of the n-day exploit alerts.
- **`two_level_terms_aggregated`**: Failed on specific queries attempting to correlate Conpot honeypot events with source IPs. This blocked attribution for the `kamstrup_protocol` activity.
- **Weakened Conclusions**: Confidence in the `BCM-2` mapping is reduced to Medium/Provisional. Attribution for the `kamstrup_protocol` activity (`ODD-1`) and `CVE-2023-46604` alerts is blocked entirely.

### 13) Agent Action Summary (Audit Trail)
- **agent_name**: ParallelInvestigationAgent
- **purpose**: Perform initial broad-spectrum data collection across different telemetry types.
- **inputs_used**: `investigation_start`, `investigation_end`
- **actions_taken**: Executed parallel queries for baseline stats (IPs, ASNs, ports), known signals (signatures, CVEs), credential noise (usernames, passwords), and honeypot-specific data (Tanner paths, Conpot protocols).
- **key_results**: Provided the foundational dataset, identifying high-volume SMB traffic (445), VNC scanning, DoublePulsar and CVE alerts, and anomalous Kamstrup protocol events.
- **errors_or_gaps**: None at this stage.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Sift through initial telemetry, apply provisional exclusions, and generate high-signal candidates for investigation.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`
- **actions_taken**: Merged inputs. Ran deeper correlation queries (`two_level_terms_aggregated`), OSINT checks (`search`), and IP-specific pivots (`top_http_urls_for_src_ip`). Synthesized findings into a structured candidate list.
- **key_results**:
    - Identified and characterized multi-exploit scanner `94.191.45.228` (BCM-1).
    - Provisionally linked SMB traffic from `180.165.27.87` to DoublePulsar alerts (BCM-2).
    - Identified anomalous Kamstrup ICS protocol activity (ODD-1).
    - Flagged CVE-2023-46604 alerts for monitoring (MON-1).
    - Classified commodity traffic (SSH brute-force, VNC) for exclusion.
- **errors_or_gaps**: Encountered multiple tool failures (`kibanna_discover_query`, `suricata_lenient_phrase_search`, `top_src_ips_for_cve`) that blocked key IP-to-alert correlations.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: Control the iterative validation of candidates.
- **inputs_used**: `candidate_discovery_result`
- **actions_taken**: Iterations run: 0. The agent immediately requested to exit the loop.
- **key_results**: The discovery phase was deemed sufficient, and no further iterative validation was required. The workflow proceeded directly to OSINT enrichment.
- **errors_or_gaps**: None.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: Control deep-dive investigations into complex or novel candidates.
- **inputs_used**: N/A
- **actions_taken**: This agent did not run as no candidates were promoted for deep investigation.
- **key_results**: N/A
- **errors_or_gaps**: N/A

- **agent_name**: OSINTAgent
- **purpose**: Validate and enrich triage candidates with open-source intelligence.
- **inputs_used**: `candidate_discovery_result`
- **actions_taken**: Performed `search` queries for all four candidates: `BCM-1` (IP `94.191.45.228`), `BCM-2` (IP `180.165.27.87`), `ODD-1` (Kamstrup protocol), and `MON-1` (CVE-2023-46604).
- **key_results**:
    - Confirmed `94.191.45.228` is a known abusive IP, reducing novelty.
    - Found no public link for `180.165.27.87` and DoublePulsar.
    - Confirmed Kamstrup protocol is for ICS/OT and remote scanning is anomalous, increasing concern.
    - Confirmed `CVE-2023-46604` is under active, widespread exploitation.
- **errors_or_gaps**: None.

- **agent_name**: ReportAgent
- **purpose**: Builds finale report from workflow state (no new searching).
- **inputs_used**: All previous workflow state outputs.
- **actions_taken**: Compiled all available evidence, triage summaries, query failures, and OSINT findings into this final report structure.
- **key_results**: This report.
- **errors_or_gaps**: None.

- **agent_name**: SaveReportAgent
- **purpose**: Persist the final report to storage.
- **inputs_used**: Final report content from ReportAgent.
- **actions_taken**: (Pending execution) Will call `investigation_write_file` tool.
- **key_results**: (Pending execution)
- **errors_or_gaps**: (Pending execution)