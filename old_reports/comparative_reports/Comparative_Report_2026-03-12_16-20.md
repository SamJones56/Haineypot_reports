# Threat Hunting Final Report

## 1. Investigation Scope
- **investigation_start**: `2026-03-12T16:00:09Z`
- **investigation_end**: `2026-03-12T20:00:09Z`
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true. The initial candidate discovery phase was impaired by tool query failures that blocked visibility into source IPs for the top observed threats (CVE-2025-55182) and odd-service activity (Conpot/Kamstrup). This required follow-on investigation loops to manually recover the necessary evidence, weakening the initial automated triage.

## 2. Executive Triage Summary
- **Top Services of Interest**: The most significant activity targeted Web (HTTP) services on a wide range of ports (80, 8080, 3000-series, 5601, 8888). Secondary services of interest included Industrial Control System (ICS) protocols (Kamstrup) and VNC (5901-5903).
- **Top Confirmed Exploitation**: Widespread, active exploitation of the recently disclosed critical RCE vulnerability **CVE-2025-55182 (React2Shell)** was the most prominent threat identified, with 171 events observed.
- **Novel Exploit Candidates**: No novel or potential zero-day exploit candidates were validated during this window.
- **Botnet/Campaign Mapping Highlights**: A multi-faceted campaign exploiting CVE-2025-55182 was identified and mapped. The investigation differentiated at least three distinct actor profiles with varying TTPs:
    - **Basic Scanners**: Used common browser user agents for broad reconnaissance.
    - **Advanced Scanners**: Used custom tooling (`Go-http-client/1.1`) and more sophisticated payloads designed to evade simple defenses.
    - **Post-Exploitation Actors**: Demonstrated successful compromise, followed by attempts to deploy webshells and download secondary payloads using `wget`.
- **Major Uncertainties**: The initial triage was significantly weakened by backend query failures, which hid the source and scale of the top CVE threat until the deep investigation phase.

## 3. Candidate Discovery Summary
The discovery phase successfully identified several areas of interest by merging baseline, known signal, and honeypot-specific data. Key candidates included widespread VNC scanning, targeted web application vulnerability probing, unusual ICS protocol interactions, and a high volume of alerts for CVE-2025-55182. However, this stage was materially affected by failed queries to enrich the CVE and ICS activity with source IP data, requiring manual validation and deep investigation to resolve.

## 4. Emerging n-day Exploitation
- **CVE/Signature Mapping**:
  - **CVE-2025-55182 (React2Shell)**
  - Associated Signatures:
    - `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
    - `ET HUNTING Javascript Prototype Pollution Attempt via __proto__ in HTTP Body`
    - `ET HUNTING Javascript Sandbox Escape via Global Object (process)`
    - `ET WEB_SERVER WebShell Generic - wget http - POST`
- **Evidence Summary**:
  - A total of 171 events were directly attributed to CVE-2025-55182 across multiple source IPs.
  - Deep investigation confirmed that this activity was not merely scanning but included post-exploitation behavior from at least one actor.
- **Affected Service/Port**:
  - HTTP on a wide variety of ports, including but not limited to 80, 3000, 3001-3011, 3030, 5601, 8080, and 8888.
- **Confidence**: High
- **Operational Notes**: This is an active and ongoing exploitation campaign for a critical, recently disclosed RCE vulnerability. The actors demonstrate a range of capabilities, from simple scanning to confirmed compromise. All associated indicators should be treated as high priority.

## 6. Botnet/Campaign Infrastructure Mapping
### item_id: CAM-01 (Multi-faceted Exploitation of CVE-2025-55182)
- **campaign_shape**: Spray (many sources, many targets)
- **suspected_compromised_src_ips**: The campaign consists of at least three distinct actor groups with different TTPs and infrastructure.
  - **Group A (Basic Scanners)**: Focused on broad reconnaissance.
    - IPs: `193.32.162.28`, `195.3.221.86`
    - ASNs / Geo: AS47890 (Romania), AS201814 (Poland)
    - TTPs: Used common browser User-Agents. Triggered initial React2Shell and Prototype Pollution alerts.
  - **Group B (Advanced Scanner)**: Used more sophisticated tooling, likely to evade basic WAF/IDS.
    - IP: `188.166.164.48`
    - ASN / Geo: AS14061 (DigitalOcean, Germany)
    - TTPs: Used a custom `Go-http-client/1.1` User-Agent. Triggered a "Javascript Sandbox Escape" alert, indicating a more advanced payload.
  - **Group C (Post-Exploitation Actor)**: Demonstrated successful compromise, followed by attempts to deploy webshells and download secondary payloads using `wget`.
    - IP: `193.26.115.178`
    - ASN / Geo: United States
    - TTPs: Used a unique User-Agent fingerprint: `Mozilla/5.0 (rondo2012@atomicmail.io)`. Followed initial exploit with post-exploitation attempts, triggering webshell and `wget` download alerts.
- **suspected_staging indicators**: No external staging hosts were identified; the attacks were direct-to-target.
- **suspected_c2 indicators**: None identified. Post-exploitation activity points to downloading further tools, but the destinations were not captured.
- **confidence**: High
- **operational notes**: All identified source IPs should be blocked. Network defenders should hunt for the unique User-Agent `Mozilla/5.0 (rondo2012@atomicmail.io)` and alerts related to "Javascript Sandbox Escape" or "wget" following a CVE-2025-55182 alert, as this indicates a likely compromise.

## 7. Odd-Service / Minutia Attacks
- **service_fingerprint**: `kamstrup_protocol` / Kamstrup Smart Metering
- **why it’s unusual/interesting**: Interaction with an Industrial Control System (ICS) protocol is highly unusual in general internet traffic and suggests reconnaissance against specialized, high-value energy infrastructure.
- **evidence summary**: 16 events were logged by the Conpot honeypot interacting with this protocol.
- **confidence**: Medium
- **recommended monitoring pivots**: While OSINT confirms this protocol can be used for legitimate remote meter reading, its appearance on a honeypot is anomalous. Monitor for any further interactions with ICS protocols or IPs targeting energy-sector ports. The initial query to identify the source of this traffic failed and should be re-run in the next window.

## 8. Known-Exploit / Commodity Exclusions
- **VNC Reconnaissance Scanning**: Widespread activity (20,652 events) characterized by the informational signature `GPL INFO VNC server response`. This is considered benign internet background noise.
- **Common Web Vulnerability Scanning**: Targeted probes for known web application vulnerabilities, including Laravel RCE (CVE-2021-3129 via `/_ignition/execute-solution`) and ThinkPHP RCE. This activity matches common automated scanner behavior.
- **Credential Noise & Brute-Force**: Standard SSH and other login attempts using common username (`root`, `admin`) and password (`123456`, `password`) lists. No unusual patterns were detected.

## 9. Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The investigation clearly distinguished between scanning and active exploitation. The CVE-2025-55182 campaign included actors engaged in both, with one group (`193.26.115.178`) moving to post-exploitation. All other activity was classified as scanning or reconnaissance.
- **Campaign Shape**: The CVE-2025-55182 campaign was a geographically distributed "spray" campaign.
- **Infra Reuse Indicators**: The attackers exploiting CVE-2025-55182 used distinct infrastructure (IPs, ASNs) and tools (User-Agents), indicating multiple independent actors rather than a single coordinated botnet.
- **Odd-Service Fingerprints**: The `kamstrup_protocol` interaction stands out as the only significant odd-service activity.

## 10. Evidence Appendix
### Emerging n-day Item: CVE-2025-55182 Campaign
- **Source IPs with Counts (Events)**:
  - `193.32.162.28` (approx. 1909 total events, subset related to CVE)
  - `188.166.164.48` (approx. 1054 total events, subset related to CVE)
  - `195.3.221.86` (approx. 919 total events, subset related to CVE)
  - `193.26.115.178` (approx. 62 total events, subset related to CVE)
- **ASNs with Counts (Providers)**:
  - AS14061 (DigitalOcean, LLC)
  - AS47890 (Unmanaged Ltd)
  - AS201814 (MEVSPACE sp. z o.o.)
- **Target Ports/Services**: 80, 3000-3011, 3030, 5601, 8080, 8888 (HTTP)
- **Paths/Endpoints**: `/`, `/_next`, `/_next/server`, `/api`, `/api/route`, `/app`
- **Payload/Artifact Excerpts (via Signatures)**:
  - `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
  - `ET HUNTING Javascript Prototype Pollution Attempt via __proto__ in HTTP Body`
  - `ET HUNTING Javascript Sandbox Escape via Global Object (process)`
  - `ET WEB_SERVER WebShell Generic - wget http - POST`

## 11. Indicators of Interest
- **High-Confidence Malicious IPs**:
  - `193.26.115.178` (Confirmed post-exploitation activity)
  - `188.166.164.48` (Advanced payload/tooling)
  - `193.32.162.28`
  - `195.3.221.86`
- **High-Confidence Malicious Artifacts**:
  - User-Agent: `Mozilla/5.0 (rondo2012@atomicmail.io)`
  - User-Agent: `Go-http-client/1.1`
- **Key Signatures to Monitor**:
  - `ET HUNTING Javascript Sandbox Escape via Global Object (process)`
  - `ET WEB_SERVER WebShell Generic - wget http - POST`

## 12. Backend Tool Issues
- **`top_src_ips_for_cve`**: This tool failed during the Candidate Discovery phase for `CVE-2025-55182`. This was a critical failure that hid the most significant threat in the dataset, forcing the validation loop to manually recover the source IPs. The initial triage conclusion was significantly weakened by this issue.
- **`two_level_terms_aggregated`**: This tool failed to return data for `type.keyword:Conpot`, which contradicted the HoneypotSpecific agent's report of 23 Conpot events. This blocked the initial analysis of the `kamstrup_protocol` activity.

## 13. Agent Action Summary (Audit Trail)
- **ParallelInvestigationAgent**:
  - **Purpose**: To run baseline, known signal, credential noise, and honeypot-specific data collection in parallel.
  - **Inputs Used**: `investigation_start`, `investigation_end`.
  - **Actions Taken**: Executed all four sub-agents (`BaselineAgent`, `KnownSignalAgent`, `CredentialNoiseAgent`, `HoneypotSpecificAgent`).
  - **Key Results**: Successfully gathered broad telemetry, identifying VNC scans, CVE-2025-55182 alerts, and Kamstrup protocol events as key signals.
  - **Errors_or_Gaps**: None.
- **CandidateDiscoveryAgent**:
  - **Purpose**: To merge parallel results and discover threat candidates.
  - **Inputs Used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
  - **Actions Taken**: Aggregated data to identify clusters of activity. Attempted to enrich candidates with source IP data.
  - **Key Results**: Identified candidates `BOT-01`, `BOT-02`, `ODD-01`, and `MIN-01`.
  - **Errors_or_Gaps**: The agent entered a `degraded_mode` due to two critical tool failures: `top_src_ips_for_cve` failed for CVE-2025-55182, and `two_level_terms_aggregated` failed for Conpot. This blocked key validation steps.
- **CandidateValidationLoopAgent**:
  - **Purpose**: To validate and enrich candidates from the discovery phase.
  - **Inputs Used**: `candidate_discovery_result`.
  - **Actions Taken**: Ran for 1 iteration, focusing on the provisionally-triaged candidate `MIN-01`. Used `suricata_cve_samples` to successfully recover the source IPs missed during discovery.
  - **Key Results**: Validated and re-classified `MIN-01` from "Suspicious Unmapped" to "Emerging n-day Exploitation," providing the first clear evidence of the actors involved.
  - **Errors_or_Gaps**: None.
- **DeepInvestigationLoopController**:
  - **Purpose**: To perform a deep-dive investigation on high-confidence, validated candidates.
  - **Inputs Used**: `validated_candidates` (`MIN-01`).
  - **Actions Taken**: Ran for 6 iterations. Consumed the lead for `MIN-01` and systematically investigated the 3 initial source IPs. Pivoted on a newly discovered advanced signature and a unique user agent, uncovering a fourth malicious IP.
  - **Key Results**: Successfully mapped the CVE-2025-55182 campaign, identifying three distinct actor profiles with different TTPs, including one actor (`193.26.115.178`) engaged in post-exploitation.
  - **Errors_or_Gaps**: None.
- **OSINTAgent**:
  - **Purpose**: To provide external context on candidates using public threat intelligence.
  - **Inputs Used**: `candidate_discovery_result`, `validated_candidates`.
  - **Actions Taken**: Performed searches for artifacts related to Kamstrup protocol, common web scanning paths, VNC signatures, and CVE-2025-55182.
  - **Key Results**: Confirmed CVE-2025-55182 is a known, critical n-day vulnerability. Confirmed the web and VNC scanning activity is commodity. Provided context on Kamstrup protocol, reducing its novelty but confirming its unusual nature.
  - **Errors_or_Gaps**: None.
- **ReportAgent**:
  - **Purpose**: To compile the final report from all workflow state outputs.
  - **Inputs Used**: All available state keys.
  - **Actions Taken**: Assembled this report.
  - **Key Results**: Report generated.
  - **Errors_or_Gaps**: None.
- **SaveReportAgent**:
  - **Purpose**: To save the final report artifact.
  - **Inputs Used**: Final report content.
  - **Actions Taken**: Will call `deep_agent_write_file`.
  - **Key Results**: File write pending.
  - **Errors_or_Gaps**: None.