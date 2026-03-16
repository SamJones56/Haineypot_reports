# Honeypot Threat Intelligence Report

## 1) Investigation Scope

*   **investigation_start**: 2026-03-07T09:00:08Z
*   **investigation_end**: 2026-03-07T12:00:08Z
*   **completion_status**: Partial
*   **degraded_mode**: true (Initial data retrieval issues prevented full characterization of some threats, though primary leads were pursued.)

## 2) Executive Triage Summary

*   A total of 24,733 attacks were observed within the 3-hour timeframe.
*   Widespread commodity scanning was detected, prominently targeting VNC (17,463 hits) from diverse ASNs and countries, and SMB (1,397 hits) from a concentrated source in Qatar.
*   Significant activity on numerous non-standard ports (e.g., 3333, 9999, 6789) originated primarily from a Google LLC IP, strongly suggesting reconnaissance for exposed cryptocurrency miners.
*   ICS/IoT honeypot (Conpot) identified activity targeting Kamstrup and Guardian AST protocols, indicating reconnaissance against industrial control systems.
*   `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` alerts (1,679 hits) were observed, but detailed source IP information could not be retrieved.
*   Standard SSH brute-forcing attempts with common credentials were widespread.
*   No novel exploit candidates or confirmed zero-days were identified.
*   Key uncertainties remain regarding the source IPs for the DoublePulsar activity and the full payload details of the Conpot ICS interactions due to degraded evidence retrieval.

## 3) Candidate Discovery Summary

A total of 24733 attacks were observed within the reporting window.
Top attacking countries included United States (6770), India (6289), Singapore (2609), Qatar (1397), and Australia (1138).
Top destination ports of interest were 5901 (VNC), 445 (SMB), 22 (SSH), and a variety of non-standard ports such as 9999, 3333, 6789, 10000, 50100.
Key detected alert signatures included `GPL INFO VNC server response` (17463 events), `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` (1679 events), and `ET SCAN MS Terminal Server Traffic on Non-standard Port` (617 events).
Four initial candidates were identified for further investigation: one suspicious unmapped monitor (later reclassified to odd-service), one odd-service/minutia attack, and two botnet/campaign mapping items.
Candidate discovery was partially degraded due to:
*   Failed queries to retrieve source IPs for the `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` signature.
*   Inability to retrieve raw Conpot events for deeper payload inspection, hindering full characterization of ICS activity.

## 4) Emerging n-day Exploitation

None.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)

None.

## 6) Botnet/Campaign Infrastructure Mapping

*   **BCM-VNC-SCAN-001: Widespread VNC Scanning**
    *   item_id: BCM-VNC-SCAN-001
    *   campaign_shape: spray
    *   suspected_compromised_src_ips: `143.244.131.140`, `168.144.22.238`, `134.209.37.134`, `165.245.138.210`
    *   ASNs / geo hints: DigitalOcean, LLC (AS14061), Alibaba US Technology Co., Ltd. (AS45102), Akamai Connected Cloud (AS63949). Activity observed from at least 5 countries.
    *   suspected_staging indicators: None identified.
    *   suspected_c2 indicators: None identified.
    *   confidence: High
    *   operational notes: This is a high-volume, commodity reconnaissance campaign targeting VNC services. IPs should be considered for blocklisting. Further correlation with other malicious activity is recommended. OSINT confirms this is established tooling.

*   **BCM-SMB-SCAN-001: High-Volume SMB Scanning**
    *   item_id: BCM-SMB-SCAN-001
    *   campaign_shape: fan-in
    *   suspected_compromised_src_ips: `178.153.127.226` (1397 hits)
    *   ASNs / geo hints: Ooredoo Q.S.C. (AS8781), Qatar.
    *   suspected_staging indicators: None identified.
    *   suspected_c2 indicators: None identified.
    *   confidence: High
    *   operational notes: This activity is consistent with known botnet campaigns targeting SMB (port 445). The source IP and ASN should be monitored for other malicious activity. OSINT confirms this is established botnet behavior.

## 7) Odd-Service / Minutia Attacks

*   **SUM-UNUSUAL-PORTS-001: Cryptocurrency Miner Reconnaissance**
    *   service_fingerprint: TCP ports `3333`, `9999`, `6000`, `10000`, `50100`, `9338`, `9674`, `2083`, `4767`, `21271`, `3797`, `3806`, `8081`, `8088`, `5001`, `5002`, `6789`, `7003`, `7382`, `11211`, `6379`, `2375`, `9200`, `33895`, `4400`, `43389`.
    *   why it’s unusual/interesting: A wide array of non-standard ports are targeted, with particular focus on port 3333, which OSINT confirms is commonly associated with cryptocurrency mining software APIs and stratum protocols. The Suricata alert for "MS Terminal Server Traffic on Non-standard Port" on port 3333 is likely a misclassification of this traffic.
    *   evidence summary: A primary scanning IP `136.114.97.84` generated 754 events, targeting various ports including 152 events for port 9999, 122 for port 3333, and 116 for port 6789.
    *   confidence: High
    *   recommended monitoring pivots: The primary scanning IP `136.114.97.84` (AS396982) and the set of targeted non-standard ports should be continuously tracked for any evolution from scanning to exploitation.

*   **OSMA-CONPOT-001: ICS/IoT Protocol Scanning**
    *   service_fingerprint: `kamstrup_management_protocol`, `guardian_ast` (on Conpot honeypot)
    *   why it’s unusual/interesting: Interaction with industrial control system (ICS) and IoT-related protocols on the honeypot indicates reconnaissance activity specifically targeting operational technology (OT) environments.
    *   evidence summary: 60 protocol hits were observed on the Conpot honeypot, with 38 for `kamstrup_management_protocol`, 20 for `guardian_ast`, and 2 for `kamstrup_protocol`.
    *   confidence: Moderate
    *   recommended monitoring pivots: Investigate the source IPs of the Conpot activity. Monitor for specific commands or payload characteristics if full event data becomes available. OSINT confirms these are known protocols for meters and tank gauges, reducing the novelty.
    *   provisional: true

## 8) Known-Exploit / Commodity Exclusions

*   **VNC Scanning**: High-volume scanning (17463 events detected by `GPL INFO VNC server response` signature) for open VNC services, a routine reconnaissance activity.
*   **DoublePulsar Backdoor Communication**: Alerts for `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` (1679 events) indicate attempts to interact with known backdoor infrastructure.
*   **Web Application Scanning**: Scans for sensitive files such as `/.env` and `/.git/config` (8 path hits) are characteristic of common web application vulnerability scanning.
*   **SSH Brute-Force**: Widespread credential stuffing/brute-force attempts using common usernames (`root`, `user`, `admin`, `ubuntu`) and weak passwords (`123456`, `password`).
*   **MS Terminal Server Traffic on Non-standard Port**: The `ET SCAN MS Terminal Server Traffic on Non-standard Port` (617 events) signature is largely associated with misclassified cryptocurrency miner scanning on port 3333.

## 9) Infrastructure & Behavioral Classification

*   **Exploitation vs. Scanning**: The majority of observed activity is reconnaissance and scanning across various services. There are indications of attempts to interact with known exploits (DoublePulsar), but no confirmed successful exploitation within the honeypot environment.
*   **Campaign Shape**:
    *   **VNC Scanning (BCM-VNC-SCAN-001)**: Exhibits a "spray" pattern, originating from a wide distribution of source IPs, ASNs (DigitalOcean, Alibaba, Akamai), and countries.
    *   **SMB Scanning (BCM-SMB-SCAN-001)**: Displays a "fan-in" pattern, largely concentrated from a single ASN (Ooredoo Q.S.C.) in Qatar.
    *   **Cryptocurrency Miner Reconnaissance (SUM-UNUSUAL-PORTS-001)**: Characterized by a "fan-out" pattern, driven primarily by a single high-volume scanner within a large cloud ASN (Google LLC) targeting multiple non-standard ports.
*   **Infra Reuse Indicators**: AS396982 (Google LLC) serves as a source for multiple distinct scanning activities, including the persistent crypto miner scanner and other lower-volume reconnaissance. This indicates a "platform abuse" model where various actors utilize the cloud provider's infrastructure independently, rather than a single coordinated campaign.
*   **Odd-Service Fingerprints**: Detection of ICS/IoT-related protocols (Kamstrup, Guardian AST) on the Conpot honeypot highlights targeted reconnaissance of specialized industrial or embedded systems.

## 10) Evidence Appendix

*   **SUM-UNUSUAL-PORTS-001: Cryptocurrency Miner Reconnaissance**
    *   source IPs with counts: `136.114.97.84` (754 total events, targeting various ports)
    *   ASNs with counts: AS396982 (Google LLC, total 1363 events from this ASN, 754 from `136.114.97.84`)
    *   target ports/services: TCP ports `3333`, `9999`, `6789`, `9009`, `4400`, `33895`, `43389`, and others.
    *   paths/endpoints: N/A (port scanning).
    *   payload/artifact excerpts: Suricata alert `ET SCAN MS Terminal Server Traffic on Non-standard Port` (ID 2023753) associated with port 3333 traffic.
    *   staging indicators: None.
    *   temporal checks results: Active from `2026-03-07T09:00:21.000Z` to `2026-03-07T12:00:02.316Z` (present throughout the investigation window).

*   **OSMA-CONPOT-001: ICS/IoT Protocol Scanning**
    *   source IPs with counts: Not directly available from aggregated output for this item, but inferred from general honeypot logs.
    *   ASNs with counts: Not directly available.
    *   target ports/services: Services associated with `kamstrup_management_protocol` and `guardian_ast` (on Conpot honeypot).
    *   paths/endpoints: Honeytrap inputs included `USER test
`, `GET / HTTP/1.0`, `OPTIONS rtsp://134.199.242.175 RTSP/1.0`. A key artifact was `b'\x01I20100'` which is a known Guardian AST command.
    *   payload/artifact excerpts: `USER test
`, `$CCGPQ,GGA[CR][LF]`, `b'\x01I20100'`, `OPTIONS rtsp://...`.
    *   staging indicators: None.
    *   temporal checks results: Unavailable.

*   **BCM-VNC-SCAN-001: Widespread VNC Scanning**
    *   source IPs with counts: `143.244.131.140` (3528), `168.144.22.238` (2522), `134.209.37.134` (453), `165.245.138.210` (315).
    *   ASNs with counts: DigitalOcean, LLC (AS14061, 9654 events), Alibaba US Technology Co., Ltd. (AS45102, 2002 events), Akamai Connected Cloud (AS63949, 1538 events).
    *   target ports/services: TCP ports `5901`, `5902`, `5903`, `5904`, `5905`, `5906`, `5907`, `5912`, `5913` (VNC default and extended range).
    *   paths/endpoints: N/A (protocol scanning).
    *   payload/artifact excerpts: `GPL INFO VNC server response` (Suricata signature 2100560).
    *   staging indicators: None.
    *   temporal checks results: Unavailable.

*   **BCM-SMB-SCAN-001: High-Volume SMB Scanning**
    *   source IPs with counts: `178.153.127.226` (1397 events targeting port 445).
    *   ASNs with counts: Ooredoo Q.S.C. (AS8781, 1397 events).
    *   target ports/services: TCP port `445` (SMB).
    *   paths/endpoints: N/A (SMB protocol scanning).
    *   payload/artifact excerpts: No specific payloads available in inputs beyond port scan indicators.
    *   staging indicators: None.
    *   temporal checks results: Unavailable.

## 11) Indicators of Interest

*   **Source IPs**:
    *   `136.114.97.84` (Primary scanner for crypto miners)
    *   `143.244.131.140` (High-volume VNC scanner)
    *   `168.144.22.238` (High-volume VNC scanner)
    *   `178.153.127.226` (High-volume SMB scanner)
*   **ASNs**:
    *   `AS396982` (Google LLC)
    *   `AS14061` (DigitalOcean, LLC)
    *   `AS8781` (Ooredoo Q.S.C.)
*   **Target Ports (TCP)**:
    *   `3333` (Cryptocurrency Miner APIs/Stratum, misclassified as RDP)
    *   `9999` (Unusual Scanning)
    *   `6789` (Unusual Scanning)
    *   `445` (SMB)
    *   `5901` (VNC)
*   **Suricata Signatures**:
    *   `GPL INFO VNC server response` (ID: 2100560)
    *   `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` (ID: 2024766)
    *   `ET SCAN MS Terminal Server Traffic on Non-standard Port` (ID: 2023753)
*   **ICS/IoT Protocols (Honeypot Observed)**:
    *   `kamstrup_management_protocol`
    *   `guardian_ast`

## 12) Backend Tool Issues

*   **CandidateDiscoveryAgent**:
    *   **Failed Query**: `two_level_terms_aggregated(primary_field='alert.signature.keyword', secondary_field='src_ip.keyword', type_filter='ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication')`
        *   Reason: No results returned.
        *   Affected Validation: Blocked retrieval of source IPs for the DoublePulsar campaign.
    *   **Failed Query**: `suricata_lenient_phrase_search(field='src_ip.keyword', phrase='ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication')`
        *   Reason: No results returned.
        *   Affected Validation: Blocked retrieval of source IPs for the DoublePulsar campaign.
    *   **Failed Query**: `two_level_terms_aggregated(primary_field='alert.category.keyword', secondary_field='src_ip.keyword', type_filter='Attempted Administrator Privilege Gain')`
        *   Reason: No results returned.
        *   Affected Validation: Unable to identify specific source IPs associated with "Attempted Administrator Privilege Gain" category alerts.
    *   **Failed Query**: `kibanna_discover_query(term='type.keyword', value='Conpot')`
        *   Reason: No results returned.
        *   Affected Validation: Unable to retrieve raw Conpot events for detailed payload inspection, weakening analysis of the ICS activity.
*   **DeepInvestigationAgent**:
    *   **Tool Error**: `two_level_terms_aggregated` was called with `type_filter='136.114.97.84'` and `primary_field='src_ip.keyword'`.
        *   Reason: Incorrect parameter usage for `type_filter` with `src_ip.keyword` as primary field.
        *   Affected Validation: Minor; the necessary data about target ports for `136.114.97.84` was successfully retrieved via the `first_last_seen_src_ip` tool.

These issues resulted in a partial completion status due to degraded evidence, particularly for DoublePulsar source attribution and granular Conpot event analysis.

## 13) Agent Action Summary (Audit Trail)

*   **ParallelInvestigationAgent**:
    *   purpose: Gather baseline, known signals, credential noise, and honeypot-specific telemetry.
    *   inputs_used: `investigation_start`, `investigation_end`.
    *   actions_taken: Executed 10 distinct data retrieval queries (e.g., `get_total_attacks`, `get_alert_signature`, `get_input_usernames`, `conpot_protocol`) across its sub-agents.
    *   key_results: Recorded 24733 total attacks, identified top 5 countries, top 5 source IPs, top 5 ASNs, and top 5 port-per-country pairs. Detected 17463 VNC server responses and 1679 DoublePulsar alerts. Summarized top usernames and passwords, OS distributions, and honeypot-specific inputs/protocols (e.g., Kamstrup, Guardian AST, Tanner paths).
    *   errors_or_gaps: None.

*   **CandidateDiscoveryAgent**:
    *   purpose: Identify and classify initial threat candidates from aggregated telemetry.
    *   inputs_used: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    *   actions_taken: Attempted 4 queries to find exploitation signals and raw honeypot events. Identified 4 initial candidates.
    *   key_results: Generated a triage summary. Identified 2 botnet/campaign mapping candidates, 1 odd-service/minutia attack candidate, and 1 suspicious unmapped monitor candidate (later validated as odd-service). Set `degraded_mode: true`.
    *   errors_or_gaps: 4 failed queries (2 for DoublePulsar related data, 1 for Admin Privilege Gain, 1 for Conpot raw events) and 2 blocked validation steps (retrieving DoublePulsar source IPs, Conpot payload inspection).

*   **CandidateValidationLoopAgent**:
    *   purpose: Orchestrate validation of discovered candidates.
    *   inputs_used: Candidates from `CandidateDiscoveryAgent`.
    *   actions_taken: 1 iteration run. Utilized `two_level_terms_aggregated` and `kibanna_discover_query` to examine `SUM-UNUSUAL-PORTS-001`.
    *   key_results: Successfully validated 1 candidate (`SUM-UNUSUAL-PORTS-001`), changing its status from provisional to confirmed.
    *   errors_or_gaps: None for the validated candidate.

*   **DeepInvestigationLoopController**:
    *   purpose: Conduct in-depth investigation of high-signal leads.
    *   inputs_used: `validated_candidates` (specifically `SUM-UNUSUAL-PORTS-001`).
    *   actions_taken: 4 iterations run. Pursued 4 key leads (`src_ip:136.114.97.84`, `asn:396982`, `service:3333`, `src_ip:147.185.133.82`). Performed 6 queries (`first_last_seen_src_ip`, `kibanna_discover_query`, `search`, `events_for_src_ip`).
    *   key_results: Confirmed `136.114.97.84` as a persistent crypto miner scanner across the full window. Characterized ASN 396982 (Google LLC) as a source of diverse, uncoordinated scanning ("platform abuse"). Contextualized port 3333 scanning as likely targeting crypto miners. Determined `147.185.133.82` was an unrelated, low-volume scanner.
    *   errors_or_gaps: One `two_level_terms_aggregated` query failed due to incorrect parameter usage. Loop exited due to stall count (2) after primary leads were thoroughly investigated, as no new high-signal leads emerged.

*   **OSINTAgent**:
    *   purpose: Provide external context and knownness mapping for candidates.
    *   inputs_used: `SUM-UNUSUAL-PORTS-001`, `OSMA-CONPOT-001`, `BCM-VNC-SCAN-001`, `BCM-SMB-SCAN-001` (from candidate_discovery_result and validated_candidates).
    *   actions_taken: Executed 6 `search` queries for terms like "TCP port 3333 standard service", "ASN 396982 abuse", "kamstrup_management_protocol", "guardian_ast protocol", "GPL INFO VNC server response suricata", and "port 445 scanning campaigns botnet".
    *   key_results: Publicly mapped crypto miner scanning, clarified ICS protocols, and confirmed VNC/SMB scanning as established commodity activity. All relevant candidates were enriched with OSINT.
    *   errors_or_gaps: None.

*   **ReportAgent**:
    *   purpose: Compile the final report from workflow state outputs.
    *   inputs_used: All previous agent outputs.
    *   actions_taken: Compiled report.
    *   key_results: Generated this markdown report.
    *   errors_or_gaps: None.

*   **SaveReportAgent**:
    *   purpose: Save the final report to storage.
    *   inputs_used: Final markdown report content.
    *   actions_taken: Implicitly called the file writing tool.
    *   key_results: (Output not provided in workflow state. Assumed successful file write.)
    *   errors_or_gaps: Missing explicit output for file write status.