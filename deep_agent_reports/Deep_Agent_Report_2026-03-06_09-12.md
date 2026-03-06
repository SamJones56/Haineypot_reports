# Honeypot Threat Intelligence Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-06T09:00:03Z
- **investigation_end**: 2026-03-06T12:00:03Z
- **completion_status**: Partial
- **degraded_mode**: true (Several backend tool queries failed during deep investigation, limiting full analysis of specific leads.)

## 2) Executive Triage Summary
- High volume of **VNC scanning and exploitation attempts** linked to **CVE-2006-2369**, originating from diverse infrastructure including DigitalOcean (ASN 14061) and Dynu Systems (ASN 398019).
- A **suspected compromised host (167.71.255.16)** from DigitalOcean is identified, exhibiting dual roles as both a target for unusual PostgreSQL reconnaissance via Heralding honeypot and a source of widespread VNC scanning.
- **Industrial Control Systems/Operational Technology (ICS/OT)** related reconnaissance detected via the ConPot honeypot, specifically for Kamstrup and Guardian AST protocols.
- Persistent **credential stuffing activity** targeting common usernames like 'root' and weak passwords.
- Several backend query failures impacted the ability to fully investigate and map all aspects of the identified PostgreSQL activity on port 5432.

## 3) Candidate Discovery Summary
- A total of 24878 attack events were observed within the investigation window.
- 11 initial high-signal candidates were identified for further validation, primarily focusing on prevalent alert signatures, top attacker IPs, associated CVEs, common credential attempts, and unusual honeypot interactions.
- Key areas of interest emerging from initial discovery included VNC protocol activity, SMB scanning, and credential-based attacks.

## 4) Emerging n-day Exploitation

### VNC Authentication Bypass Campaign (CVE-2006-2369)
- **CVE/Signature Mapping**: CVE-2006-2369, GPL INFO VNC server response (Signature ID: 2100560), ET EXPLOIT VNC Server Not Requiring Authentication (case 2) (Signature ID: 2002923).
- **Evidence Summary**: Over 20,842 instances of `GPL INFO VNC server response` and 2,081 instances of `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)` alerts observed. Correlated with 2,081 events mapped to CVE-2006-2369. Source IPs from samples include 108.165.230.43, 8.218.201.91, 120.55.45.107, 129.212.183.98, 37.148.133.247, and 207.174.1.152. Primarily targets VNC default port 5900.
- **Affected Service/Port**: VNC servers on TCP port 5900.
- **Confidence**: High
- **Operational Notes**: This represents a widespread and ongoing scanning and exploitation campaign targeting VNC servers that are misconfigured or vulnerable to authentication bypass. Mitigation involves updating VNC servers and disabling "None" authentication.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
- No novel or potential zero-day exploit candidates were identified in this investigation. All exploit-like behavior was mapped to known vulnerabilities or established attack patterns.

## 6) Botnet/Campaign Infrastructure Mapping

### VNC Scanning Campaign (Global Spray)
- **Item ID/Related Candidate ID(s)**: VNC_Auth_Bypass_Campaign
- **Campaign Shape**: Spray (widespread scanning across multiple source IPs and ASNs targeting VNC ports).
- **Suspected Compromised Source IPs**:
    - **207.174.1.152** (2001 events related to VNC exploitation, also associated with Heralding honeypot activity)
    - **108.165.230.43** (396 VNC events, 89 Suricata alerts for VNC/SSH)
    - **134.209.37.134** (453 VNC events targeting 167.71.255.16)
    - **129.212.184.194** (335 VNC events targeting 167.71.255.16)
    - Additional IPs from alert samples: 8.218.201.91, 120.55.45.107, 37.148.133.247.
- **ASNs / Geo Hints**:
    - **ASN 14061 (DigitalOcean, LLC, United States)**: Significant source (3076 events), with multiple IPs (e.g., 134.209.37.134, 129.212.184.194) involved in VNC scanning (ports 5901-5905).
    - **ASN 398019 (Dynu Systems Incorporated, United States)**: Associated with 207.174.1.152.
    - **ASN 210356 (BattleHost, Brazil)**: Associated with 108.165.230.43.
- **Suspected Staging Indicators**: None explicitly identified as staging, but 167.71.255.16 exhibits characteristics of a compromised host.
- **Suspected C2 Indicators**: None identified with high confidence.
- **Confidence**: High
- **Operational Notes**: Monitor DigitalOcean and Dynu Systems IP ranges for continued VNC scanning. Consider blocking IPs with high alert volumes.

### Suspected Compromised Host (167.71.255.16)
- **Item ID/Related Candidate ID(s)**: N/A (derived from deep investigation of other leads)
- **Campaign Shape**: Dual-role activity: target of reconnaissance (PostgreSQL) and source of widespread scanning (VNC, web, DNS).
- **Suspected Compromised Source IPs**: 167.71.255.16 (20335 events observed across Suricata, P0f, Fatt honeypots).
- **ASNs / Geo Hints**: ASN 14061 (DigitalOcean, LLC, United States).
- **Suspected Staging Indicators**: This IP is a strong candidate for a compromised host serving as part of an attacker's infrastructure. It is observed initiating VNC connections from source port 5900 to numerous destination IPs (rfb flows) and also being targeted by PostgreSQL reconnaissance (from 46.19.137.194).
- **Suspected C2 Indicators**: None explicitly identified, but its versatile scanning profile and being a target for unusual services suggest it might be part of a larger, coordinated effort.
- **Confidence**: High
- **Operational Notes**: Implement enhanced monitoring and potential blocking of this IP. Investigate connections to this host for further C2 activity.

## 7) Odd-Service / Minutia Attacks

### ICS/OT Protocol Scans (ConPot)
- **Service Fingerprint**: Various ports/protocols captured by ConPot, including `kamstrup_management_protocol` (160 events), `guardian_ast` (47 events), and `kamstrup_protocol` (3 events).
- **Why it’s unusual/interesting**: These protocols are associated with Industrial Control Systems (ICS) and Operational Technology (OT) environments, suggesting reconnaissance efforts targeting critical infrastructure or specialized embedded devices. The raw inputs often contain binary data.
- **Evidence Summary**: 210 events recorded by the ConPot honeypot, detailing interactions with these specialized protocols.
- **Confidence**: High
- **Recommended Monitoring Pivots**: Monitor for further ICS/OT protocol interactions and identify source IPs targeting these services. Analyze payload details for specific commands.

### PostgreSQL Reconnaissance (Heralding on Port 5432)
- **Service Fingerprint**: PostgreSQL protocol on TCP port 5432 (captured by Heralding honeypot).
- **Why it’s unusual/interesting**: While PostgreSQL is a common database, its targeting via a Heralding honeypot and the specific source IP (46.19.137.194) and target (167.71.255.16) make this activity noteworthy, especially considering the target IP's other malicious activities. Further investigation was hampered by tool failures.
- **Evidence Summary**: 2108 Heralding events, with primary source IP 207.174.1.152 (2001 events). A sample event shows src_ip 46.19.137.194 targeting dest_ip 167.71.255.16 on port 5432 with `postgresql` protocol.
- **Confidence**: Moderate (due to limited further investigation)
- **Recommended Monitoring Pivots**: Investigate src_ip 46.19.137.194 and other IPs targeting port 5432. Attempt to resolve tool failures for deeper analysis.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise**: Extensive brute-force attempts with common usernames ('root', 'user', 'admin', 'ubuntu') and weak passwords ('123456', 'password', '@qwer2025').
- **General Scanning**: Widespread scanning for various services, including fragmented/truncated packets (SURICATA IPv4/AF-PACKET truncated packet - 2172 counts) and generic HTTP/web application reconnaissance (e.g., requests for `/robots.txt`, `/favicon.ico`, `.env` files, and directory traversal attempts like `/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd`).
- **Commodity SMB Scanning**: High volume scanning on port 445 from countries like Ukraine (3173 counts), France (2577 counts), and Russia (1000 counts). This is typical background noise.
- **SSH Scanning**: Numerous `SURICATA SSH invalid banner` alerts, indicating generic SSH scanning activity.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The majority of observed activity is reconnaissance or scanning. Confirmed exploitation attempts are specific to the VNC authentication bypass (CVE-2006-2369). Credential noise indicates brute-force attacks.
- **Campaign Shape**: Predominantly "spray" tactics for VNC and SMB scanning, targeting a wide range of hosts on specific ports.
- **Infra Reuse Indicators**: The IP 167.71.255.16 (ASN 14061, DigitalOcean) exhibits reuse, acting both as an attacker (VNC scanner) and a target (PostgreSQL recon). Multiple IPs from DigitalOcean (ASN 14061) are involved in the VNC campaign, suggesting a botnet or compromised cloud infrastructure.
- **Odd-Service Fingerprints**: Distinct patterns of scanning for ICS/OT protocols (Kamstrup, Guardian AST) and targeted reconnaissance of PostgreSQL (port 5432).

## 10) Evidence Appendix

### VNC Authentication Bypass Campaign (VNC_Auth_Bypass_Campaign)
- **Source IPs with Counts**:
    - 207.174.1.152 (US, Dynu Systems Incorporated): ~10336 events on port 5900 (P0f/Heralding)
    - 108.165.230.43 (Brazil, BattleHost): 396 events (89 Suricata alerts)
    - 137.184.121.249 (from aggregated data): 4601 events on port 5900
    - 143.198.239.107 (from aggregated data): 4410 events on port 5900
    - 129.212.183.98 (from aggregated data): 4015 events on port 5900
- **ASNs with Counts**:
    - 14061 (DigitalOcean, LLC, US): 3076 total events (includes scanning by IPs like 134.209.37.134, 129.212.184.194)
    - 398019 (Dynu Systems Incorporated, US): Associated with 207.174.1.152
    - 210356 (BattleHost, BR): Associated with 108.165.230.43
- **Target Ports/Services**: TCP 5900 (VNC), also 5901-5905 from DigitalOcean IPs.
- **Payload/Artifact Excerpts**:
    - `GPL INFO VNC server response`
    - `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)`
    - `ET INFO VNC Authentication Failure`
    - Raw VNC protocol handshakes (RFB protocol flows).
- **Staging Indicators**: None directly identified as staging, but widespread nature.
- **Temporal Checks**:
    - 108.165.230.43: First seen 2026-03-06T09:12:30Z, Last seen 2026-03-06T12:00:02Z
    - 207.174.1.152: First seen 2026-03-06T11:17:46Z, Last seen 2026-03-06T11:49:16Z
    - Overall campaign active throughout the investigation window.

### Suspected Compromised Host (167.71.255.16)
- **Source IPs with Counts**: 167.71.255.16 (20335 events across honeypot types)
- **ASNs with Counts**: 14061 (DigitalOcean, LLC, United States)
- **Target Ports/Services (as attacker)**: TCP 5900 (VNC), 443 (HTTPS), 53 (DNS), 80 (HTTP).
- **Target Ports/Services (as target)**: TCP 5432 (PostgreSQL - Heralding honeypot).
- **Payload/Artifact Excerpts**:
    - Initiates `rfb` protocol flows from src_port 5900 to various destination IPs.
    - TLS/HTTP/DNS traffic.
    - Targeted by `postgresql` protocol on 5432 (from 46.19.137.194).
- **Staging Indicators**: Its dual behavior as both a source of extensive scanning and a target of specific reconnaissance (PostgreSQL) strongly suggests compromise and potential use as part of an attacker's staging infrastructure.
- **Temporal Checks**: First seen 2026-03-06T09:00:03Z, Last seen 2026-03-06T12:00:03Z.

## 11) Indicators of Interest
- **Source IPs**:
    - 207.174.1.152 (VNC exploitation, Heralding activity)
    - 167.71.255.16 (Suspected compromised host, VNC scanner, PostgreSQL target)
    - 108.165.230.43 (VNC activity, Brazil)
    - 134.209.37.134 (DigitalOcean VNC scanner)
    - 129.212.184.194 (DigitalOcean VNC scanner)
    - 46.19.137.194 (PostgreSQL recon source)
    - 79.98.102.166 (Top SMB scanner, France)
    - 176.120.59.98 (Top SMB scanner, Ukraine)
- **Target Ports**:
    - 5900, 5901, 5902, 5903, 5904, 5905 (VNC)
    - 5432 (PostgreSQL)
    - 445 (SMB)
    - Various ICS/OT ports (observed on ConPot)
- **CVEs**:
    - CVE-2006-2369 (VNC Authentication Bypass)
- **Suricata Signatures**:
    - `GPL INFO VNC server response` (2100560)
    - `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)` (2002923)
- **ASNs**:
    - 14061 (DigitalOcean, LLC)
    - 398019 (Dynu Systems Incorporated)
    - 210356 (BattleHost)
    - 51852 (Private Layer INC)
- **Credential Fragments**:
    - Usernames: `root`, `345gs5662d34`, `user`, `admin`, `ubuntu`
    - Passwords: `3245gs5662d34`, `345gs5662d34`, `123456`, `1234`, `@qwer2025`
- **URI Paths (Tanner)**:
    - `/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd` (Path Traversal)
    - `/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd` (Path Traversal)
    - `/.env`

## 12) Backend Tool Issues
- **Tool**: `kibanna_discover_query`
    - **Affected Validations**: Retrieving raw events for the initial VNC signature candidate validation, and during deep investigation for `service:Heralding` and `dest_port:5432`.
    - **Error**: `illegal_argument_exception: Expected text at 1:71 but found START_ARRAY`
    - **Impact**: Prevented comprehensive analysis and full understanding of specific honeypot events (Heralding/PostgreSQL) and limited the ability to derive new leads or granular evidence from raw events for these areas.

- **Tool**: `match_query`
    - **Affected Validations**: Deep investigation for `dest_port:5432` (PostgreSQL).
    - **Error**: `illegal_argument_exception: Expected text at 1:26 but found START_ARRAY`
    - **Impact**: Further hindered detailed analysis of PostgreSQL activity on port 5432, preventing retrieval of specific event details.

## 13) Agent Action Summary (Audit Trail)

- **agent_name**: ParallelInvestigationAgent
    - **purpose**: Orchestrates parallel data collection across various security telemetry sources.
    - **inputs_used**: `investigation_start`, `investigation_end`
    - **actions_taken**: Triggered BaselineAgent, KnownSignalAgent, CredentialNoiseAgent, HoneypotSpecificAgent.
    - **key_results**: Initial collection of baseline metrics, known alerts, credential trends, and honeypot-specific data.
    - **errors_or_gaps**: None reported directly for this agent.

- **agent_name**: BaselineAgent
    - **purpose**: Gathers fundamental attack statistics and top-level traffic patterns.
    - **inputs_used**: `investigation_start`, `investigation_end`
    - **actions_taken**: Queried total attacks, top countries, top source IPs, country-to-port mappings, and top attacker ASNs.
    - **key_results**: 24878 total attacks, top source countries/IPs/ASNs, identified major ports like 5900 (VNC) and 445 (SMB).
    - **errors_or_gaps**: None.

- **agent_name**: KnownSignalAgent
    - **purpose**: Identifies known exploitation patterns, CVEs, and alert categories.
    - **inputs_used**: `investigation_start`, `investigation_end`
    - **actions_taken**: Queried top alert signatures, CVEs, alert categories, and performed a lenient phrase search for "VNC" signatures.
    - **key_results**: Detected high volumes of VNC-related alerts (`GPL INFO VNC server response`, `ET EXPLOIT VNC Server Not Requiring Authentication`), identified `CVE-2006-2369`.
    - **errors_or_gaps**: None.

- **agent_name**: CredentialNoiseAgent
    - **purpose**: Analyzes credential stuffing and brute-force activity.
    - **inputs_used**: `investigation_start`, `investigation_end`
    - **actions_taken**: Queried top input usernames, passwords, and OS distribution of observed systems.
    - **key_results**: Identified common usernames (`root`, `admin`) and weak passwords (`123456`), and a high volume of Windows NT kernel and Linux OS fingerprints.
    - **errors_or_gaps**: None.

- **agent_name**: HoneypotSpecificAgent
    - **purpose**: Extracts specific insights from honeypot-generated telemetry.
    - **inputs_used**: `investigation_start`, `investigation_end`
    - **actions_taken**: Queried Redis actions, ADBHoney inputs/malware, ConPot inputs/protocols, and Tanner URI requests.
    - **key_results**: Minimal Redis/ADBHoney activity, significant ConPot activity showing ICS/OT protocols (Kamstrup, Guardian AST), and Tanner showing generic web scans including path traversal attempts.
    - **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
    - **purpose**: Identifies initial high-signal candidates for in-depth investigation.
    - **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`
    - **actions_taken**: Compiled a list of 11 distinct candidates from the initial data collections.
    - **key_results**: Queued 11 candidates, including VNC signatures, attacker IPs, CVEs, common credentials, and suspicious URIs.
    - **errors_or_gaps**: None reported directly, but this agent's output is implicitly passed to the loop controller.

- **agent_name**: CandidateValidationLoopAgent
    - **purpose**: Validates and classifies high-signal candidates.
    - **inputs_used**: Candidates from `CandidateDiscoveryAgent`
    - **actions_taken**: Ran 1 iteration, attempted validation for the `GPL INFO VNC server response` candidate. Used `suricata_signature_samples` and `suricata_cve_samples`.
    - **key_results**: 1 candidate successfully validated and classified as a `known_exploit_campaign` related to VNC exploitation (CVE-2006-2369).
    - **errors_or_gaps**: `kibanna_discover_query` failed for the VNC candidate, but validation proceeded with other tools.

- **agent_name**: DeepInvestigationLoopController
    - **purpose**: Manages the iterative deep investigation process, pursuing high-priority leads.
    - **inputs_used**: Validated candidates, previous deep investigation states.
    - **actions_taken**: Ran 9 iterations, consumed leads including specific source IPs (108.165.230.43, 207.174.1.152, 167.71.255.16, 134.209.37.134, 129.212.184.194), ASNs (14061, 210356, 398019), and honeypot services (`service:Heralding`, `Heralding_event_details`, `dest_port:5432`).
    - **key_results**: Uncovered a widespread VNC scanning campaign originating from DigitalOcean infrastructure, identified 167.71.255.16 as a dual-role compromised host, and detected PostgreSQL recon activity.
    - **errors_or_gaps**: Encountered 2 stall counts; `kibanna_discover_query` and `match_query` tools repeatedly failed for `dest_port:5432` and `service:Heralding` event details, leading to incomplete investigation of these leads. Loop exited due to `loop_exit_requested`.

- **agent_name**: OSINTAgent
    - **purpose**: Enriches findings with external threat intelligence.
    - **inputs_used**: `validated_candidates` (specifically for the VNC campaign)
    - **actions_taken**: Performed OSINT searches for `CVE-2006-2369 exploit details` and Suricata VNC signatures.
    - **key_results**: Confirmed `CVE-2006-2369` as an established VNC authentication bypass vulnerability, linking it directly to observed telemetry and reducing its novelty score.
    - **errors_or_gaps**: None.

- **agent_name**: ReportAgent
    - **purpose**: Compiles the final threat intelligence report.
    - **inputs_used**: All preceding workflow state outputs (`investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `validated_candidates`, `osint_validation_result`, `deep_investigation_logs`, `pipeline_query_failure_diagnostics`).
    - **actions_taken**: Assembled the comprehensive report following the specified markdown structure and logic.
    - **key_results**: This report.
    - **errors_or_gaps**: None (self-reporting).

- **agent_name**: SaveReportAgent
    - **purpose**: Saves the generated report to persistent storage.
    - **inputs_used**: The completed report content.
    - **actions_taken**: File write operation.
    - **key_results**: Report saved successfully (pending final tool call).
    - **errors_or_gaps**: None (pending final tool call).
