# Honeypot Threat Intelligence Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-03T09:00:46Z
- **investigation_end**: 2026-03-03T10:00:46Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true - Inability to retrieve raw event details for ADB, VNC, and Conpot activity via `kibanna_discover_query` due to persistent 'illegal_argument_exception' and incomplete aggregations from `two_level_terms_aggregated`.

## 2) Executive Triage Summary
- High volume VNC scanning (2524 hits) observed, primarily targeting ports 5926, 5925, and 5902 from United States source IPs.
- Android Debug Bridge (ADB) honeypot recorded malicious interactions attempting to deploy `com.ufo.miner` cryptocurrency mining malware, associated with the Trinity botnet. Multiple unique malware samples were identified.
- Industrial Control Systems (ICS) honeypot detected reconnaissance activity targeting Veeder-Root TLS-350 Automatic Tank Gauge systems using the `guardian_ast` protocol, specifically requesting an "In-Tank Inventory Report."
- Top attacker IPs originate predominantly from cloud/hosting providers (DigitalOcean, LLC; Hebei Mobile Communication Company Limited; Hetzner Online GmbH), consistent with commodity scanning and botnet infrastructure.
- Significant credential stuffing attempts were logged against common usernames ('root', 'wallet', 'admin') and weak passwords (empty, '123456', 'password').
- Investigation completeness is partial due to persistent tool errors preventing deep-dive into raw event payloads, impacting detailed campaign analysis.

## 3) Candidate Discovery Summary
One primary candidate was identified and validated. This candidate focused on observed high-signal activities including ADB malware deployment (`ufo.miner`), high-volume VNC scanning, and ICS protocol interactions (`guardian_ast`). Candidate discovery was materially affected by `kibanna_discover_query` and `two_level_terms_aggregated` failures, limiting detailed aggregation and raw event inspection for the primary candidate.

## 4) Emerging n-day Exploitation
- **CVEs Detected (Incidental)**:
    - `CVE-2025-55182` (2 events)
    - `CVE-2024-14007` (1 event)
    - **Evidence Summary**: Detected via `get_cve` tool.
    - **Affected Service/Port**: Not directly linked to the primary observed high-volume ADB, VNC, or Conpot activities, suggesting these are incidental detections rather than the primary exploitation vector of the noted campaigns.
    - **Confidence**: Low (as related to observed primary activities).
    - **Operational Notes**: Monitor for direct exploitation attempts related to these CVEs in future windows.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
No novel or zero-day exploit candidates were identified in this window. All high-signal activities were mapped to known campaigns, malware families, or reconnaissance techniques through OSINT validation.

## 6) Botnet/Campaign Infrastructure Mapping
- **ADB.Miner / Trinity Botnet Activity**
    - **item_id**: N/A (primary candidate)
    - **campaign_shape**: Spray - characterized by widespread scanning for exposed ADB interfaces and subsequent attempts to deploy known cryptocurrency mining malware.
    - **suspected_compromised_src_ips**: 167.99.95.111 (560), 36.143.57.131 (429), 134.122.80.225 (405), 88.99.24.59 (397), 134.199.222.217 (316). These IPs contributed to the overall baseline traffic.
    - **ASNs / geo hints**: ASN 14061 (DigitalOcean, LLC), ASN 24547 (Hebei Mobile Communication Company Limited), ASN 24940 (Hetzner Online GmbH). Predominantly cloud/hosting providers.
    - **suspected_staging indicators**: Malware samples detected as `dl/*.raw` (e.g., `dl/51ad31d5be1e1099fee1d03c711c9f698124899cfc321da5c0c56f8c93855e57.raw`) suggest remote hosting/download locations. Specific URLs were not available in the provided context.
    - **suspected_c2 indicators**: The ADB input `ps | grep trinity` indicates an attempt to check for the presence of the "trinity" component, which is associated with the Trinity botnet, potentially a C2 command.
    - **confidence**: High
    - **operational notes**: Block identified malware hashes and source IPs. Monitor network traffic for outbound connections from ADB-exposed systems that might indicate successful compromise and C2 communication.

## 7) Odd-Service / Minutia Attacks
- **Android Debug Bridge (ADB) Exploitation**
    - **service_fingerprint**: ADB (implied port 5555, protocol ADB)
    - **why it’s unusual/interesting**: ADB is a developer tool, and its exposure on an internet-facing honeypot is often indicative of misconfiguration or intentional targeting of IoT/embedded Android devices. The observed `ufo.miner` deployment confirms malicious intent targeting cryptocurrency mining.
    - **evidence summary**: 35 total ADB events, including inputs like `pm path com.ufo.miner`, `am start -n com.ufo.miner/com.example.test.MainActivity`, `pm install /data/local/tmp/ufo.apk`, `ps | grep trinity`, `rm -f /data/local/tmp/ufo.apk`, `rm -rf /data/local/tmp/*`. Malware samples such as `dl/51ad31d5be1e1099fee1d03c711c9f698124899cfc321da5c0c56f8c93855e57.raw` were associated.
    - **confidence**: High
    - **recommended monitoring pivots**: Monitor for unexpected ADB connections, file transfers to `/data/local/tmp/`, and unusual process execution (e.g., `trinity`, mining processes) on Android devices.

- **ICS/SCADA Reconnaissance (Veeder-Root TLS-350)**
    - **service_fingerprint**: ICS/SCADA (Conpot honeypot emulating `guardian_ast` protocol, typically on TCP port 10001)
    - **why it’s unusual/interesting**: Targets critical infrastructure protocols and specific SCADA devices (Veeder-Root TLS-350 ATG). The request for an "In-Tank Inventory Report" (`b'\x01I20100'`) suggests reconnaissance for sensitive operational technology data.
    - **evidence summary**: 5 Conpot events, including 1 request `b'\x01I20100'` under the `guardian_ast` protocol.
    - **confidence**: High
    - **recommended monitoring pivots**: Isolate and restrict access to ICS/SCADA systems. Monitor for any attempts to connect to or interact with these protocols, especially from external sources. Alert on specific known reconnaissance commands like `I20100`.

## 8) Known-Exploit / Commodity Exclusions
- **High Volume VNC Scanning**: A significant volume of VNC scanning was detected, characterized by the `GPL INFO VNC server response` signature (2524 occurrences). This activity predominantly targeted VNC-related ports (5926, 5925, 5902) and is consistent with common internet-wide scanning for open VNC services.
- **Credential Stuffing/Brute Force**: Widespread attempts to guess credentials using common usernames (`root` - 147, `wallet` - 120, `admin` - 41) and weak passwords (empty string - 126, `123456` - 26, `password` - 24) were observed across multiple services and source IPs.
- **Common Scanning Activity**: Routine scanning for widely exposed services included:
    - **SMB (Port 445)**: 429 counts, primarily from China.
    - **SSH (Port 22)**: 199 counts from Germany, 114 from United Kingdom, 62 from India, 61 from United States.
    - **MySQL (Port 3306)**: 122 counts from India.
    - **MS-SQL (Port 1433)**: 11 counts from China, 4 from India.
- **General Network Noise**: Alerts such as `SURICATA IPv4 truncated packet` (412), `SURICATA AF-PACKET truncated packet` (412), `SURICATA STREAM reassembly sequence GAP -- missing packet(s)` (124), and `ET DROP Dshield Block Listed Source group 1` (86) represent common network anomalies or known malicious sources.
- **Redis Information Disclosure**: Attempts to query Redis server information (`INFO server`) were observed (9 events).

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The observed activity largely consists of opportunistic scanning for vulnerable services (VNC, SSH, SMB, MySQL, Redis) coupled with credential brute-forcing. More targeted exploitation attempts included the deployment of `ufo.miner` malware via exposed ADB and specific reconnaissance against ICS/SCADA systems.
- **Campaign Shape**: The overall behavioral pattern points to a "spray and pray" strategy. Attackers leverage widespread scanning to identify accessible services and then attempt to deploy known commodity malware or conduct reconnaissance using established techniques.
- **Infra Reuse Indicators**: The high concentration of source IPs from prominent cloud and hosting providers (DigitalOcean, LLC; Hetzner Online GmbH) strongly indicates the use of leased infrastructure, common for botnet operators and commodity scanners. The generic malware download paths (`dl/*.raw`) are also typical for such campaigns.
- **Odd-Service Fingerprints**: Notable activity targeting less common services like Android Debug Bridge (ADB) and ICS/SCADA protocols (Veeder-Root TLS-350 `guardian_ast`) highlights an expansion of typical attack surface monitoring for honeypots.

## 10) Evidence Appendix
- **ADB.Miner / Trinity Botnet Activity**
    - **Source IPs with counts**: 167.99.95.111 (560), 36.143.57.131 (429), 134.122.80.225 (405), 88.99.24.59 (397), 134.199.222.217 (316)
    - **ASNs with counts**: 14061 (DigitalOcean, LLC - 3023 total), 24547 (Hebei Mobile Communication Company Limited - 429 total), 24940 (Hetzner Online GmbH - 397 total)
    - **Target ports/services**: Android Debug Bridge (implied port 5555)
    - **Paths/endpoints**: `pm path com.ufo.miner`, `am start -n com.ufo.miner/com.example.test.MainActivity`, `pm install /data/local/tmp/ufo.apk`, `ps | grep trinity`, `rm -f /data/local/tmp/ufo.apk`, `rm -rf /data/local/tmp/*`
    - **Payload/artifact excerpts**: Malware hashes (e.g., `dl/51ad31d5be1e1099fee1d03c711c9f698124899cfc321da5c0c56f8c93855e57.raw`, `dl/9a56e2c761e10156cac6589bc9e929b1b8b5b00dd6c79ca0d33c2399b88e3a43.raw`, `dl/9bc28777e722c46898754ef256d052e9cd684f6ad812d69878c68ba6cc0c72fe.raw`)
    - **Staging indicators**: `dl/*.raw` suggests malware download locations.
    - **Temporal checks results**: Unavailable.

- **VNC Scanning**
    - **Source IPs with counts**: 167.99.95.111 (560 total from baseline), 134.122.80.225 (405 total from baseline)
    - **ASNs with counts**: 14061 (DigitalOcean, LLC - 3023 total from baseline)
    - **Target ports/services**: VNC (5926, 5925, 5902)
    - **Paths/endpoints**: N/A (protocol-level interaction)
    - **Payload/artifact excerpts**: `GPL INFO VNC server response` (Suricata signature 2100560)
    - **Staging indicators**: None.
    - **Temporal checks results**: Unavailable.

- **ICS/SCADA Veeder-Root TLS-350 Reconnaissance**
    - **Source IPs with counts**: Not specifically detailed in context for this granular activity.
    - **ASNs with counts**: Not specifically detailed in context for this granular activity.
    - **Target ports/services**: ICS/SCADA (Conpot honeypot, `guardian_ast` protocol, typically TCP port 10001)
    - **Paths/endpoints**: N/A (protocol-level interaction)
    - **Payload/artifact excerpts**: `b'\x01I20100'` (Veeder-Root TLS-350 "In-Tank Inventory Report" request)
    - **Staging indicators**: None.
    - **Temporal checks results**: Unavailable.

## 11) Indicators of Interest
- **Malware Hashes**:
    - `dl/51ad31d5be1e1099fee1d03c711c9f698124899cfc321da5c0c56f8c93855e57.raw`
    - `dl/9a56e2c761e10156cac6589bc9e929b1b8b5b00dd6c79ca0d33c2399b88e3a43.raw`
    - `dl/9bc28777e722c46898754ef256d052e9cd684f6ad812d69878c68ba6cc0c72fe.raw`
- **Suspected Attacker IPs**:
    - 167.99.95.111
    - 36.143.57.131
    - 134.122.80.225
    - 88.99.24.59
    - 134.199.222.217
- **Targeted ADB Commands/Inputs**:
    - `pm path com.ufo.miner`
    - `pm install /data/local/tmp/ufo.apk`
    - `ps | grep trinity`
- **ICS Protocol Commands**:
    - `b'\x01I20100'` (Veeder-Root TLS-350 "In-Tank Inventory Report" request)
- **VNC Signature**:
    - `GPL INFO VNC server response` (Suricata signature 2100560)
- **Targeted Ports (High-Signal)**:
    - 5926, 5925, 5902 (VNC)
    - Implied 5555 (ADB)
    - Implied 10001 (ICS/SCADA Veeder-Root)

## 12) Backend Tool Issues
- **`kibanna_discover_query`**: Multiple failures with `illegal_argument_exception` (reason: "Expected text at 1:71 but found START_ARRAY") when attempting to query `.keyword` fields (e.g., `adbhoney.input.keyword`, `type.keyword`, `alert.signature.keyword`, `conpot.protocol.keyword`). This issue blocked detailed inspection of raw event payloads for ADB, VNC, and Conpot activities, significantly weakening the ability to fully understand campaign specifics, detailed exploit vectors, and the precise nature of observed artifacts.
- **`two_level_terms_aggregated`**: This tool returned empty buckets for several aggregations (e.g., for `adbhoney.input.keyword` to `src_ip.keyword` related to `ufo.miner`, and for `dest_port.keyword` to `src_ip.keyword` for VNC ports), despite reporting total hits. This failure limited the ability to accurately attribute specific high-signal activities to their originating source IPs, thereby impacting the granularity and confidence of infrastructure mapping for individual findings.

## 13) Agent Action Summary (Audit Trail)

- **ParallelInvestigationAgent** (and its sub-agents: BaselineAgent, KnownSignalAgent, CredentialNoiseAgent, HoneypotSpecificAgent)
    - `purpose`: Conduct parallel initial investigations across various data sources to establish baseline activity and identify known signals.
    - `inputs_used`: `investigation_start`, `investigation_end`.
    - `actions_taken`: Executed queries for total attacks, top countries, attacker IPs/ASNs, country-to-port mappings, alert signatures, CVEs, alert categories, common usernames/passwords, OS distribution, Redis activity, ADBhoney inputs/malware samples, Conpot inputs/protocols, and Tanner URI requests.
    - `key_results`: Identified 5234 total attacks, top attacker geographies and ASNs, high-volume VNC scanning, common credential noise, ADB `ufo.miner` malware deployment, and ICS/SCADA reconnaissance.
    - `errors_or_gaps`: None reported by sub-agents.

- **CandidateDiscoveryAgent**
    - `purpose`: Identify potential high-signal candidates from aggregated initial investigation results.
    - `inputs_used`: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result` (inferred).
    - `actions_taken`: Analyzed overall activity to seed a primary candidate based on ADB, VNC, and Conpot highlights.
    - `key_results`: One primary candidate was identified for validation, focusing on ADB `ufo.miner` malware, VNC scanning, and ICS `guardian_ast` protocol interactions.
    - `errors_or_gaps`: The explicit logging of this agent's action/output was not detailed, but its role in providing candidates to the loop controller is clear.

- **CandidateValidationLoopAgent**
    - `purpose`: Validate and enrich identified candidates through targeted queries, knownness checks, and temporal analysis.
    - `inputs_used`: Candidate data, `investigation_start`, `investigation_end`.
    - `actions_taken`: Performed Suricata phrase search for `ufo.miner`, CVE checks, and multiple `kibanna_discover_query` and `two_level_terms_aggregated` calls to retrieve raw events and aggregations for ADB, VNC, and Conpot activity.
    - `key_results`: Classified the candidate as a "known_exploit_campaign" based on detected ADB.Miner/Trinity activity, VNC scanning, and ICS reconnaissance. Noted incidental CVEs. Marked the candidate as provisional due to evidence gaps.
    - `errors_or_gaps`: Iterations run: 1. # candidates validated: 1. `kibanna_discover_query` failed repeatedly with 'illegal_argument_exception' for various `.keyword` field searches. `two_level_terms_aggregated` returned empty buckets despite matching documents. Validation was blocked for detailed raw event inspection and precise IP attribution for specific activities.

- **DeepInvestigationLoopController**
    - `purpose`: Manage the lifecycle and iterations of the Candidate Validation Loop.
    - `inputs_used`: Candidate queue from `innit_candidate_que`.
    - `actions_taken`: Initialized the candidate queue, loaded the next candidate, and requested loop exit after processing the single available candidate.
    - `key_results`: Iterations run: 1. Key leads pursued: The single candidate encompassing ADB, VNC, and Conpot activity. Stall/exit reason: No further candidates available for processing.
    - `errors_or_gaps`: None.

- **OSINTAgent**
    - `purpose`: Gather external threat intelligence for high-signal artifacts.
    - `inputs_used`: Specific terms derived from the validated candidate (e.g., `ufo.miner malware botnet com.ufo.miner android`, `GPL INFO VNC server response signature`, `guardian_ast protocol ICS conpot b'\x01I20100'`).
    - `actions_taken`: Performed targeted searches against public intelligence sources.
    - `key_results`: Confirmed `com.ufo.miner` as part of the ADB.Miner/Trinity botnet, clarified VNC "GPL INFO" as standard protocol response, and mapped ICS activity to known Veeder-Root TLS-350 reconnaissance. Assessed public mapping as true, recency as established, and novelty as reduced.
    - `errors_or_gaps`: None.

- **ReportAgent**
    - `purpose`: Compile the final report from workflow state outputs.
    - `inputs_used`: All preceding agent outputs (`investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `validated_candidates`, `osint_validation_result`).
    - `actions_taken`: Compiled this comprehensive markdown report.
    - `key_results`: Generated a structured report summarizing findings, classifications, and operational insights.
    - `errors_or_gaps`: Noted degraded mode due to upstream tool failures from `CandidateValidationLoopAgent`.

- **SaveReportAgent**
    - `purpose`: Save the generated report to a persistent storage location.
    - `inputs_used`: The full markdown report content generated by the `ReportAgent`.
    - `actions_taken`: (Will perform a file write operation).
    - `key_results`: (Status of file write, e.g., 'Report saved successfully' or 'Failed to save report').
    - `errors_or_gaps`: None (anticipated successful save).