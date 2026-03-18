# Honeypot Threat Hunting Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-18T09:00:05Z
- **investigation_end**: 2026-03-18T12:00:05Z
- **completion_status**: Complete
- **degraded_mode**: false

## 2) Executive Triage Summary
- **Top Services/Ports of Interest**: VNC (ports 5900-5903), HTTP (port 80 via Tanner honeypot), and the IEC104 ICS protocol (via Conpot honeypot).
- **Top Confirmed Known Exploitation**: Widespread scanning for VNC authentication bypass (CVE-2006-2369) was the dominant commodity activity.
- **Top Unmapped Exploit-like Items**: A reconnaissance probe targeting a PHPUnit RCE vulnerability (CVE-2017-9841) was identified. Deep investigation attributed this activity to the **RedTail cryptominer malware** based on the unique user agent `libredtail-http`.
- **Botnet/Campaign Mapping Highlights**: A large-scale VNC 'spray' campaign was identified. More significantly, reconnaissance activity from the RedTail cryptominer campaign was mapped, including the attacker's source IP and a suspected C2 server IP (`178.16.55.224`) derived from OSINT. No communication with the suspected C2 was observed.
- **Major Uncertainties**: An internal index mapping issue prevented a direct query against the `http.user_agent.keyword` field, but this was successfully bypassed using OSINT.

## 3) Candidate Discovery Summary
Initial analysis of telemetry identified four primary areas of interest:
1.  A high-volume VNC scanning and exploitation campaign (later mapped to `BOT-01`).
2.  A targeted, multi-vector PHP reconnaissance attempt from a single source IP, which included probes for PHPUnit, LFI, and XDEBUG vulnerabilities (later mapped to the RedTail cryptominer campaign).
3.  Low-volume reconnaissance against the IEC104 Industrial Control System protocol (`ODD-01`).
4.  Scanning for Spring Boot Actuator endpoints, indicative of reconnaissance for cloud infrastructure vulnerabilities.

## 4) Emerging n-day Exploitation
*No emerging n-day exploits were validated. The initial candidate related to an evasive PHPUnit exploit was re-classified as campaign reconnaissance after the reflection investigation.*

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
*No candidates met the criteria for this section.*

## 6) Botnet/Campaign Infrastructure Mapping
### VNC Scanning Campaign (BOT-01)
- **item_id**: BOT-01
- **campaign_shape**: spray (high volume from many disparate sources).
- **suspected_compromised_src_ips**: `79.124.40.98` (999 events), `165.232.109.215` (738 events), and hundreds of others.
- **ASNs / geo hints**: The campaign is distributed across multiple ASNs, with the largest clusters in AS50360 (Tamatiya EOOD, Bulgaria) and AS14061 (DigitalOcean, LLC, United States).
- **suspected_staging indicators**: None identified.
- **suspected_c2 indicators**: None identified.
- **confidence**: High.
- **operational notes**: This is a high-volume, opportunistic campaign scanning for the old and well-known VNC authentication bypass vulnerability (CVE-2006-2369). The IPs are likely compromised systems used for scanning.

### RedTail Cryptominer Reconnaissance
- **item_id or related candidate_id(s)**: NOV-01
- **campaign_shape**: fan-out (one IP probing for multiple vulnerabilities).
- **suspected_compromised_src_ips**: `154.50.110.184`.
- **ASNs / geo hints**: AS46783 (EASY LINK LLC, United States).
- **suspected_staging indicators**: None identified. The activity was direct-to-target reconnaissance.
- **suspected_c2 indicators**: `178.16.55.224` (identified via OSINT as a known RedTail C2).
- **supporting evidence / uncertainty**: The user agent `libredtail-http` from `154.50.110.184` is a known indicator for RedTail malware. OSINT confirms this malware exploits PHPUnit and Docker APIs, matching observed behavior. A search for the suspected C2 IP in the telemetry showed no communication, indicating no successful compromise was observed.
- **confidence**: High.
- **operational notes**: This actor is performing reconnaissance for vulnerabilities (PHPUnit, Docker) known to be exploited by the RedTail cryptominer. The C2 IP and user agent are high-fidelity indicators for detecting this campaign.

## 7) Odd-Service / Minutia Attacks
### ICS Protocol Reconnaissance (ODD-01)
- **service_fingerprint**: IEC104 on Conpot honeypot.
- **why it’s unusual/interesting**: IEC104 is a protocol used in Industrial Control Systems (ICS). Activity on this protocol indicates reconnaissance interest in critical infrastructure.
- **evidence summary**: A small number of events (8) were recorded. OSINT confirms this is a known target for vulnerability scanning.
- **confidence**: Low (due to volume, indicating passive scanning rather than an active attack).
- **recommended monitoring pivots**: Monitor for any increase in volume or attempts to send specific control commands over this protocol.

## 8) Known-Exploit / Commodity Exclusions
- **VNC Authentication Bypass Scanning (CVE-2006-2369)**: The majority of traffic consisted of widespread, automated scanning for this well-known VNC vulnerability.
- **Credential Noise**: Standard brute-force attempts were observed against SSH, using common usernames (`root`, `admin`) and passwords.
- **Common Web Scanning**:
    - Probing for exposed configuration files like `.env`.
    - Reconnaissance for Spring Boot Actuator endpoints (`/actuator/gateway/routes`) from `79.124.40.174`. This is a known technique to find systems vulnerable to CVE-2022-22947.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: All observed activity was classified as scanning and reconnaissance. The PHPUnit activity, while targeting an RCE vulnerability, was a `GET` request to probe for the file's existence, not deliver a payload.
- **Campaign Shape**: The VNC campaign was a distributed 'spray'. The RedTail reconnaissance was a 'fan-out' from a single IP.
- **Infra Reuse Indicators**: The actor at `79.124.40.174` was observed scanning for both Spring Boot web vulnerabilities and PostgreSQL databases. The actor at `154.50.110.184` probed for PHPUnit, LFI, and Docker vulnerabilities.
- **Odd-Service Fingerprints**: Activity on the IEC104 protocol indicates niche interest in ICS/SCADA systems.

## 10) Evidence Appendix
### RedTail Cryptominer Reconnaissance (NOV-01)
- **source IPs**: `154.50.110.184` (173 events)
- **ASNs**: 46783 (EASY LINK LLC)
- **target ports/services**: 80 (HTTP/Tanner)
- **paths/endpoints**: `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, `/containers/json`
- **payload/artifact excerpts**: User Agent: `libredtail-http`
- **staging indicators**: Suspected C2 IP (from OSINT): `178.16.55.224`. No communications observed.
- **temporal checks results**: unavailable.

### VNC Scanning Campaign (BOT-01)
- **source IPs**: `79.124.40.98` (999), `165.232.109.215` (738), `136.114.97.84` (636), and others.
- **ASNs**: 14061 (DigitalOcean, LLC), 50360 (Tamatiya EOOD), and others.
- **target ports/services**: 5900, 5901, 5902, 5903 (VNC)
- **payload/artifact excerpts**: Traffic matching 'ET EXPLOIT VNC Server Not Requiring Authentication' (CVE-2006-2369).
- **temporal checks results**: unavailable.

## 11) Indicators of Interest
- **IPs**:
    - `154.50.110.184` (High confidence; RedTail cryptominer reconnaissance).
    - `178.16.55.224` (High confidence; Suspected RedTail C2 server).
    - `79.124.40.174` (Moderate confidence; Multi-purpose scanner).
- **URIs**:
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (Reconnaissance for CVE-2017-9841).
    - `/actuator/gateway/routes` (Reconnaissance for CVE-2022-22947).
- **Artifacts**:
    - User Agent: `libredtail-http` (High confidence indicator for RedTail malware).

## 12) Reflection Findings
- **Reflection Candidates Discovered**: The workflow identified three topics for deeper analysis: (1) The potentially evasive PHPUnit exploit, (2) The multi-purpose scanning from IP `79.124.40.174`, and (3) The nature of the ICS protocol probing.
- **Actions Taken**: A deep investigation was launched on the "Evasive PHPUnit RCE Payload Analysis" candidate. The investigation traced the source IP, analyzed the raw request, and pivoted on the user agent string via OSINT.
- **Findings of Reflection**:
    1.  The activity targeting PHPUnit was a reconnaissance `GET` request, not a payload-delivering `POST` exploit. This clarified the actor's intent as probing, not exploitation.
    2.  The user agent `libredtail-http` was identified as a key indicator.
    3.  OSINT linked this user agent directly to the **RedTail cryptominer malware**, which is known to scan for the exact combination of vulnerabilities observed (PHPUnit, Docker APIs).
    4.  A suspected C2 server IP (`178.16.55.224`) for the malware was uncovered via OSINT.
    5.  A subsequent search confirmed no communications with this suspected C2 were present in the telemetry.
- **Enhancements**: The reflection phase was critical. It re-attributed a vaguely defined "evasive exploit" to a specific, named malware family (RedTail), clarified the actor's intent (reconnaissance), and uncovered a high-value C2 indicator for network defense.

## 13) Backend Tool Issues
- `two_level_terms_aggregated`: This tool failed during the reflection investigation when attempting to query on `http.user_agent.keyword`. This appears to be an internal data indexing issue, as the data was present. The analysis was not blocked, as a successful pivot to OSINT provided the necessary context.

## 14) Agent Action Summary (Audit Trail)
- **agent_name**: ParallelInvestigationAgent
- **purpose**: Gather initial broad-spectrum telemetry.
- **inputs_used**: Time window.
- **actions_taken**: Executed parallel queries for baseline stats, known alerts, credential data, and honeypot logs.
- **key_results**: Identified high VNC volume (CVE-2006-2369), standard credential stuffing, and suspicious Tanner/Conpot activity.
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Synthesize initial data to identify potential threats.
- **inputs_used**: All outputs from ParallelInvestigationAgent.
- **actions_taken**: Merged data, pivoted on suspicious Tanner paths, and formulated four initial candidates.
- **key_results**: Prioritized a potential novel PHP exploit (`NOV-01`), a VNC campaign (`BOT-01`), ICS minutia (`ODD-01`), and Spring Boot scanning (`MIN-01`).
- **errors_or_gaps**: None.

- **agent_name**: OSINTAgent
- **purpose**: Validate and contextualize candidates using public intelligence.
- **inputs_used**: `candidate_discovery_result`.
- **actions_taken**: Performed web searches for CVEs, paths, and protocols related to the candidates.
- **key_results**: Confirmed all initial candidates were related to known, established vulnerabilities or scanning patterns.
- **errors_or_gaps**: None.

- **agent_name**: ReflectionCandidateDiscoverAgent
- **purpose**: Identify areas where the initial report could be improved with deeper analysis.
- **inputs_used**: Final report content.
- **actions_taken**: Analyzed the initial report for ambiguities and high-value unanswered questions.
- **key_results**: Generated three reflection candidates, prioritizing the analysis of the "evasive" PHPUnit exploit.
- **errors_or_gaps**: None.

- **agent_name**: ReflectDeepInvestigationAgent
- **purpose**: Execute a deep-dive investigation based on a reflection candidate.
- **inputs_used**: Reflection candidate: "Evasive PHPUnit RCE Payload Analysis".
- **actions_taken**: Executed 3 iterations. Analyzed raw web logs, pivoted on a user agent string to OSINT, identified the RedTail malware family, and searched for a suspected C2 IP in telemetry.
- **key_results**: Re-classified the event as reconnaissance, not exploitation. Attributed the activity to the RedTail cryptominer via the `libredtail-http` user agent. Uncovered a suspected C2 IP `178.16.55.224` and confirmed no contact was made.
- **errors_or_gaps**: One query failed due to a suspected backend indexing issue, but the investigation proceeded successfully using OSINT.

- **agent_name**: ReportAgent
- **purpose**: Compile the final report from all workflow state outputs, including reflection findings.
- **inputs_used**: All preceding agent state outputs.
- **actions_taken**: Synthesized all data, integrating the critical findings from the reflection investigation to re-classify and add context to the RedTail malware activity. Assembled this final report.
- **key_results**: This report.
- **errors_or_gaps**: None.

- **agent_name**: SaveReportAgent
- **purpose**: Save the final report artifact.
- **inputs_used**: Final report content from ReportAgent.
- **actions_taken**: Called `deep_agent_write_file`.
- **key_results**: Report successfully saved as `Deep_Agent_Report_2026-03-18_09-12.md`.
- **errors_or_gaps**: None.