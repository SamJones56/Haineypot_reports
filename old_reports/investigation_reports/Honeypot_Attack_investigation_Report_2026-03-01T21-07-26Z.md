# Honeypot Threat Hunt - Final Report

### 1) Investigation Scope
- **investigation_start**: `2026-03-01T20:00:21Z`
- **investigation_end**: `2026-03-01T21:00:21Z`
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true. The investigation was significantly hampered by multiple backend tool failures. Key query tools (`kibanna_discover_query`, `suricata_lenient_phrase_search`, `two_level_terms_aggregated`) repeatedly failed or returned empty results for high-count events, preventing correlation of activity with source infrastructure for several key leads.

### 2) Executive Triage Summary
- **Top Services of Interest**: The most significant activity targeted SMB (TCP/445), with notable probes against ICS (kamstrup_protocol), ADB (inferred from Adbhoney), and specific web application paths (e.g., `/SDK/webLanguage`).
- **Top Confirmed Known Exploitation**: A high-volume (737 events) DoublePulsar backdoor campaign was the most prominent known threat. The activity originated from a single, dedicated source IP.
- **Botnet/Campaign Mapping Highlights**: A focused DoublePulsar scanning/exploitation campaign was identified originating from IP `106.51.79.149` in India. Additionally, Adbhoney honeypots captured malware samples associated with the known Gafgyt IoT botnet.
- **Odd-Service Activity**: Probing of the `kamstrup_protocol`, associated with smart metering / ICS environments, was observed.
- **Major Uncertainties**: Due to persistent query failures, it was not possible to identify the source IPs responsible for the Gafgyt malware downloads or the ICS protocol probing, severely limiting infrastructure mapping for these events. The full scale of the DoublePulsar campaign could not be verified beyond the single identified IP.

### 3) Candidate Discovery Summary
The discovery phase successfully identified four primary candidates for investigation from the initial telemetry: a large-scale DoublePulsar campaign, Adbhoney malware downloads, ICS protocol probing (Kamstrup), and specific web vulnerability probing (`/SDK/webLanguage`). However, subsequent enrichment queries failed for three of the four candidates, with only the web probing lead being successfully correlated with source IPs during this phase. This led to a degraded state where high-signal events could not be fully investigated.

### 4) Botnet/Campaign Infrastructure Mapping
**Item ID**: BCM-001
- **Related Candidate ID(s)**: `BCM-001-DEGRADED`
- **Campaign Shape**: Single-source scanning / fan-out
- **Suspected Compromised Source IPs**: `106.51.79.149` (783 events in ~11 minutes)
- **ASNs / Geo Hints**: ASN 24309 / AS55836 (Atria Convergence Technologies Pvt. Ltd.), India (Bengaluru)
- **Suspected Staging Indicators**: None observed.
- **Suspected C2 Indicators**: None observed. This was exploit/scanning activity.
- **Confidence**: High
- **Operational Notes**: The IP `106.51.79.149` appears to be a dedicated scanner/attacker for the DoublePulsar vulnerability (related to MS17-010). Its activity was focused and short-lived. Recommend blocking this IP. Pivoting to the surrounding CIDR (`106.51.79.0/24`) for monitoring is advised based on OSINT reports.

### 5) Odd-Service / Minutia Attacks
**Item ID**: OSM-001
- **Service Fingerprint**: `kamstrup_protocol` (Conpot Honeypot)
- **Why it's unusual/interesting**: This is a niche protocol for smart metering in Industrial Control Systems (ICS). Probing against this service is uncommon and suggests potentially targeted interest in OT/ICS infrastructure.
- **Evidence Summary**: 10 distinct interaction events were recorded. However, all attempts to query for the responsible source IPs failed due to backend tool issues.
- **Confidence**: Low (Provisional)
- **Recommended Monitoring Pivots**: Requires fixing data query tools to identify the source of these probes. Once identified, the source IP and ASN should be monitored for further ICS-related activity.

### 6) Known-Exploit / Commodity Exclusions
- **Gafgyt Botnet Propagation**: Adbhoney honeypots recorded downloads of three distinct malware samples. OSINT analysis of hash `4251293b2d3765833f16988c2dbec30362df1c84dfe33c58dcc0815596d31353` confirms its association with the Gafgyt (aka Bashlite) IoT botnet family. This is known commodity malware.
- **Commodity Credential Stuffing**: Widespread, distributed brute-force attempts against SSH (22) and Telnet (23) using common usernames (`root`, `admin`) and passwords (`123456`). This is considered internet background noise.
- **VNC Scanning**: High volume of `GPL INFO VNC server response` signatures (2,091 hits) indicates broad, non-targeted scanning for open VNC servers.
- **Low-Count Known Exploits**: A handful of alerts for known vulnerabilities like `CVE-2021-3449` (OpenSSL) and `CVE-2019-11500` (Dovecot) were observed but did not constitute a significant or coordinated campaign.

### 7) Infrastructure & Behavioral Classification
- **DoublePulsar Campaign (106.51.79.149)**: Classified as **Exploitation**. The campaign shape was **single-source scanning** from a non-reused, dedicated IP.
- **Tanner Web Probes**: Classified as **Scanning/Probing**. Activity from `79.124.40.174` (XDEBUG) and `89.42.231.241` (`/SDK/webLanguage`) was **single-source probing** for specific vulnerabilities.
- **Kamstrup ICS Probes**: Unclassified due to missing source data.
- **Gafgyt Malware Downloads**: Unclassified due to missing source data.

### 8) Evidence Appendix
**Item**: DoublePulsar Campaign (BCM-001)
- **Source IPs**: `106.51.79.149` (count: 783)
- **ASNs**: `24309` ("Atria Convergence Technologies Pvt. Ltd. Broadband Internet Service Provider INDIA")
- **Target Ports/Services**: TCP/445 (SMB)
- **Paths/Endpoints**: N/A
- **Payload/Artifact Excerpts**: Suricata Signature: `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`
- **Staging Indicators**: None
- **Temporal Checks**: First seen: `2026-03-01T20:38:15.000Z`, Last seen: `2026-03-01T20:49:31.321Z`.

### 9) Indicators of Interest
- **IPs (High Confidence)**:
    - `106.51.79.149` (DoublePulsar exploitation)
    - `79.124.40.174` (XDEBUG web probe)
    - `89.42.231.241` (`/SDK/webLanguage` web probe)
- **Malware Hashes (SHA256)**:
    - `4251293b2d3765833f16988c2dbec30362df1c84dfe33c58dcc0815596d31353` (Gafgyt)
    - `9a56e2c761e10156cac6589bc9e929b1b8b5b00dd6c79ca0d33c2399b88e3a43`
    - `9bc28777e722c46898754ef256d052e9cd684f6ad812d69878c68ba6cc0c72fe`
- **Paths**:
    - `/?XDEBUG_SESSION_START=phpstorm`
    - `/SDK/webLanguage`

### 10) Backend Tool Issues
- **`kibanna_discover_query`**: Failed repeatedly with an `illegal_argument_exception`. This blocked attempts to retrieve raw event data for the DoublePulsar campaign and Adbhoney malware downloads during the discovery phase.
- **`suricata_lenient_phrase_search`**: Returned 0 results when searching for source IPs related to the high-count DoublePulsar signature. This blocked infrastructure mapping.
- **`two_level_terms_aggregated`**: Returned empty buckets for Adbhoney, Conpot, and ASN-based queries, contradicting initial summary data.
- **Weakened Conclusions**: The inability to identify source IPs for the Gafgyt malware campaign and the Kamstrup ICS probes means their scale and origin are completely unknown. Confidence in the scope of the DoublePulsar campaign is limited to the single IP that was successfully investigated via other tools.

### 11) Agent Action Summary (Audit Trail)
- **Agent Name**: ParallelInvestigationAgent
- **Purpose**: Conduct initial broad data collection across four parallel areas.
- **Inputs Used**: `investigation_start`, `investigation_end`
- **Actions Taken**: Executed baseline, known signal, credential noise, and honeypot-specific data queries.
- **Key Results**: Generated `baseline_result`, `known_signals_result`, `credential_noise_result`, and `honeypot_specific_result` states, providing the initial data for the investigation.
- **Errors or Gaps**: None. All sub-agents completed successfully.

- **Agent Name**: CandidateDiscoveryAgent
- **Purpose**: Merge parallel results, identify initial leads, and perform enrichment queries.
- **Inputs Used**: All four outputs from the ParallelInvestigationAgent.
- **Actions Taken**: Merged inputs. Identified 4 candidate seeds (DoublePulsar, Adbhoney, Kamstrup, Web Probing). Executed 5 enrichment queries to find source IPs.
- **Key Results**: Successfully correlated web probing paths to source IPs. Failed to enrich the other three, more significant, seeds. Produced a `degraded_mode` output due to tool failures.
- **Errors or Gaps**: 4 out of 5 deep-dive queries failed (`kibanna_discover_query`, `suricata_lenient_phrase_search`, `two_level_terms_aggregated`), preventing infrastructure mapping for the most critical leads.

- **Agent Name**: CandidateValidationLoopAgent
- **Purpose**: Sequentially process and validate candidates discovered previously.
- **Inputs Used**: `candidate_discovery_result`
- **Actions Taken**: Initialized a queue of 4 candidates. Ran for 1 iteration on the 'DoublePulsar' candidate. Used `suricata_signature_samples` and `search` (OSINT) to validate the activity.
- **Key Results**: Validated the DoublePulsar activity as a `known_exploit_campaign` originating from `106.51.79.149`.
- **Errors or Gaps**: The loop did not proceed to the other candidates, handing off for a deep dive on the first one. This is expected behavior.

- **Agent Name**: DeepInvestigationLoopController
- **Purpose**: Perform a deep, multi-turn investigation on a high-confidence validated candidate.
- **Inputs Used**: `validated_candidates` (specifically, the DoublePulsar candidate)
- **Actions Taken**: Ran for 4 iterations, focusing on lead `src_ip:106.51.79.149`. Used tools `first_last_seen_src_ip`, `events_for_src_ip`, `search` (OSINT), and multiple aggregation queries.
- **Key Results**: Fully characterized the activity of `106.51.79.149` as a short, focused DoublePulsar campaign targeting TCP/445. Enriched the IP with GeoIP and OSINT data.
- **Errors or Gaps**: Pivoting from the IP to its ASN and from the signature to other IPs failed due to repeated tool errors (`two_level_terms_aggregated`, `suricata_lenient_phrase_search`), causing the investigation to stall and exit.

- **Agent Name**: OSINTAgent
- **Purpose**: Use external search tools to enrich unvalidated candidates with public threat intelligence.
- **Inputs Used**: `honeypot_specific_result`, `candidate_discovery_result`
- **Actions Taken**: Performed a search on the malware hash from the `Adbhoney` honeypot.
- **Key Results**: Successfully mapped hash `4251293b2d3765833f16988c2dbec30362df1c84dfe33c58dcc0815596d31353` to the `Gafgyt` malware family, confirming it as known commodity activity.
- **Errors or Gaps**: None.

- **Agent Name**: ReportAgent
- **Purpose**: Build the final report from all workflow state outputs.
- **Inputs Used**: All prior agent state outputs.
- **Actions Taken**: Compiled this report.
- **Key Results**: Report generated.
- **Errors or Gaps**: None.

- **Agent Name**: SaveReportAgent
- **Purpose**: Persist the final report artifact.
- **Inputs Used**: Completed report content from ReportAgent.
- **Actions Taken**: Pending downstream tool call to `investigation_write_file`.
- **Key Results**: To be determined.
- **Errors or Gaps**: None.