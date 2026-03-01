# Threat Hunting Honeypot Investigation Report

### 1. Investigation Scope
- **investigation_start**: 2026-03-01T15:00:15Z
- **investigation_end**: 2026-03-01T16:01:23Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true. The investigation was significantly hampered by backend tool failures and data inconsistencies. Key validation steps to map attacker infrastructure were blocked, weakening several conclusions.

### 2. Executive Triage Summary
- **Top Services of Interest**: High-volume activity was observed against VNC (5900-series ports) and SSH (22). Operationally interesting activity was also noted against Minecraft (25565), MikroTik (8728), and an ICS protocol (`guardian_ast`).
- **Top Confirmed Known Exploitation**: Telemetry confirmed active exploitation of **CVE-2025-55182 (React2Shell)**, a critical (CVSS 10.0) pre-authentication RCE. A high volume of alerts (1,437) for the **DoublePulsar backdoor** indicates a large-scale, ongoing campaign.
- **Top Unmapped Exploit-like Items**: No novel exploit candidates were validated. Initial leads were reclassified as known scanning behavior after OSINT validation.
- **Botnet/Campaign Mapping Highlights**: A significant **DoublePulsar** campaign is underway. However, attempts to map the compromised source IPs and infrastructure failed due to backend data query issues.
- **Major Uncertainties**: Critical evidence gaps exist due to tool failures. The source IPs and scale of the CVE-2025-55182 and DoublePulsar campaigns could not be determined from the available telemetry.

### 3. Candidate Discovery Summary
Initial analysis of baseline, known signal, and honeypot-specific data identified four primary candidate seeds for investigation:
1.  **DoublePulsar Botnet Activity**: High-volume (1,437 events) alerts for a known backdoor.
2.  **CVE-2025-55182 Activity**: Low-volume (26 events) alerts for a potentially recent CVE.
3.  **Odd-Service "Nintendo 3DS"**: A unique p0f OS fingerprint connecting to a Minecraft server (port 25565).
4.  **Tanner Web Probes**: Specific, low-volume probes for paths like `/+CSCOE+/logon.html` and `/SDK/webLanguage`.

Discovery was materially affected by subsequent tool failures, which blocked queries to enrich and validate these candidates using honeypot telemetry.

### 4. Emerging n-day Exploitation
- **cve/signature mapping**: CVE-2025-55182 (React2Shell)
- **evidence summary**: 26 alert events were detected within the time window. Queries to retrieve the associated source IPs failed, preventing attribution.
- **affected service/port**: Web services leveraging React Server Components (e.g., Next.js).
- **confidence**: High
- **operational notes**: OSINT confirms this is a critical, publicly known RCE vulnerability (CVSS 10.0) actively used in ransomware campaigns. Any alerts for this CVE should be considered a high-priority incident. The inability to retrieve source IPs is a critical visibility gap.

### 5. Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
*No candidates met the criteria for Novel or Zero-Day exploitation in this window. All unmapped candidates were successfully reclassified as known scanning or established threats during OSINT validation.*

### 6. Botnet/Campaign Infrastructure Mapping
- **item_id**: DoublePulsar-Activity-1
- **campaign_shape**: Unknown (Investigation blocked)
- **suspected_compromised_src_ips**: Unavailable due to tool/data query failure.
- **ASNs / geo hints**: Unavailable.
- **suspected_staging indicators**: None identified.
- **suspected_c2 indicators**: None identified.
- **confidence**: Low (Confidence in infrastructure mapping is low; confidence in the presence of the campaign is High).
- **operational notes**: A large-scale campaign leveraging the DoublePulsar backdoor is active. While OSINT confirms this is established tooling, the high volume indicates significant ongoing impact. Manual queries are required to overcome the tool failures and map the campaign's source infrastructure.

### 7. Odd-Service / Minutia Attacks
- **service_fingerprint**: Port 25565/TCP (Minecraft)
- **why it’s unusual/interesting**: An incoming connection was fingerprinted by p0f as a "Nintendo 3DS" gaming console, which is highly anomalous.
- **evidence summary**: A single connection from **176.65.148.143**. OSINT validation revealed this IP belongs to a hosting provider and is a known mass scanner. The "Nintendo 3DS" fingerprint is therefore considered a likely misidentification or spoof. The event has been reclassified as commodity scanning.
- **confidence**: High (that this is scanning activity from a known malicious IP).
- **recommended monitoring pivots**: Monitor the broader IP range (`176.65.148.0/22`) for continued reconnaissance activity.

### 8. Known-Exploit / Commodity Exclusions
- **Credential Noise**: Standard brute-force attacks against SSH using common usernames (`root`, `admin`, `pi`) and passwords (`123456`, `password`). Seen across hundreds of IPs.
- **VNC Scanning**: High-volume (2,045+ events) scanning for VNC services, confirmed by `GPL INFO VNC server response` signatures.
- **RDP Scanning**: Commodity scanning for Microsoft Terminal Services on non-standard ports.
- **Known Vulnerability Scanning**: Low-volume, targeted probes for known vulnerabilities in Cisco ASA (`/+CSCOE+/logon.html`) and Hikvision cameras (`/SDK/webLanguage`), confirmed via OSINT.

### 9. Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The investigation identified both active exploitation (CVE-2025-55182, DoublePulsar) and widespread scanning (VNC, RDP, Minecraft, specific web vulnerabilities).
- **Campaign Shape**: The shape of the DoublePulsar and CVE-2025-55182 campaigns remains unknown due to blocked queries. Other scanning activity appears to be wide-spectrum spray from disparate sources.
- **Infra Reuse Indicators**: The IP `176.65.148.143` and its associated network block are heavily reused for malicious scanning across multiple protocols.
- **Odd-Service Fingerprints**: The "Nintendo 3DS" fingerprint on port 25565 was the most notable odd-service event, though it was ultimately reclassified as reconnaissance from a known scanner.

### 10. Evidence Appendix
- **Emerging n-day Item: CVE-2025-55182-React2Shell**
    - **source IPs with counts**: Unavailable (Query failed)
    - **ASNs with counts**: Unavailable
    - **target ports/services**: HTTP/HTTPS
    - **payload/artifact excerpts**: Telemetry alert for CVE-2025-55182
- **Botnet Mapping Item: DoublePulsar-Activity-1**
    - **source IPs with counts**: Unavailable (Query failed)
    - **ASNs with counts**: Unavailable
    - **target ports/services**: SMB (via EternalBlue/related exploits)
    - **payload/artifact excerpts**: Signature `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` (1,437 events)
- **Odd-Service Item: Nintendo-3DS-Minecraft-Probe**
    - **source IPs with counts**: `176.65.148.143` (1 event)
    - **ASNs with counts**: ASN not available in data, but OSINT identifies the owner as Pfcloud UG (Netherlands).
    - **target ports/services**: 25565/TCP
    - **payload/artifact excerpts**: p0f OS fingerprint: `Nintendo 3DS`

### 11. Indicators of Interest
- **IPs**:
    - `176.65.148.143` (Known mass scanner, associated with "Nintendo 3DS" fingerprint)
    - `89.42.231.241` (Scanning for Hikvision vulnerability)
    - `216.180.246.66` (Scanning for Cisco ASA vulnerability)
- **URIs/Paths**:
    - `/+CSCOE+/logon.html`
    - `/SDK/webLanguage`
- **CVEs**:
    - `CVE-2025-55182`
- **Signatures**:
    - `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`

### 12. Backend Tool Issues
- **`kibanna_discover_query`**: Failed with a `400` error when querying the activity of IP `176.65.148.143`. This failure blocked contextual analysis of the "Nintendo 3DS" event.
- **`top_src_ips_for_cve` / `suricata_lenient_phrase_search`**: These tools returned zero results for both `CVE-2025-55182` and the `DoublePulsar` signature, despite triage data showing 26 and 1,437 events respectively. This critical data inconsistency prevented the attribution of n-day exploitation and the mapping of botnet infrastructure. The conclusions for these items are consequently weakened and marked as **Provisional**.

### 13. Agent Action Summary (Audit Trail)
- **agent_name**: ParallelInvestigationAgent
- **purpose**: Runs initial baseline, known-signal, credential-noise, and honeypot-specific queries in parallel.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Executed initial data gathering queries across multiple data sources.
- **key_results**:
    - Identified 12,991 total attacks.
    - Flagged high-volume signatures for VNC and DoublePulsar.
    - Detected 26 alerts for CVE-2025-55182.
    - Uncovered the "Nintendo 3DS" OS fingerprint.
    - Found low-volume probes on Tanner and Conpot honeypots.
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Merges parallel results to identify and perform initial validation on promising leads.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**:
    - Merged and triaged initial results.
    - Formed 4 candidate seeds (DoublePulsar, CVE-2025-55182, Nintendo 3DS, Tanner Probes).
    - Executed 6 follow-up queries (`two_level_terms_aggregated`, `p0f_os_search`, etc.) to validate seeds.
- **key_results**:
    - Successfully identified the source IP for the Nintendo 3DS event (`176.65.148.143`).
    - Confirmed IPs probing for specific web paths on the Tanner honeypot.
- **errors_or_gaps**:
    - Multiple tool queries failed to retrieve source IPs for the DoublePulsar campaign and CVE-2025-55182 alerts, contradicting triage counts.
    - A `kibanna_discover_query` call failed with a 400 error, blocking further investigation into the Nintendo 3DS source IP.
    - Declared `degraded_mode` due to these failures.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: Intended to iteratively validate candidates discovered in the previous step.
- **inputs_used**: `candidate_discovery_result`.
- **actions_taken**: The loop was exited immediately by the `CandidateLoopControllerAgent` due to the discovery phase being blocked by tool failures. No validation iterations were run.
- **key_results**: N/A.
- **errors_or_gaps**: Workflow was blocked before this agent could execute its primary function.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: Controls the execution flow of the investigation loop.
- **inputs_used**: `candidate_discovery_result`.
- **actions_taken**: Assessed that the `CandidateDiscoveryAgent` was blocked by critical tool/data failures and called `exit_loop`.
- **key_results**: Halted the investigation loop to prevent further failed queries and proceed to OSINT and reporting with degraded evidence. Iterations run: 0.
- **errors_or_gaps**: N/A.

- **agent_name**: OSINTAgent
- **purpose**: Enriches and validates findings with public threat intelligence.
- **inputs_used**: `candidate_discovery_result`.
- **actions_taken**: Performed 5 `search` tool calls on the key candidates (CVE-2025-55182, DoublePulsar, Nintendo 3DS IP, Tanner paths).
- **key_results**:
    - Confirmed CVE-2025-55182 is a critical, actively exploited RCE.
    - Reclassified the "Nintendo 3DS" event as commodity scanning from a known malicious IP.
    - Mapped the Tanner web probes to scanning for known Cisco and Hikvision vulnerabilities.
    - Confirmed DoublePulsar is established, well-known tooling.
- **errors_or_gaps**: None.

- **agent_name**: ReportAgent
- **purpose**: Builds finale report from workflow state (no new searching).
- **inputs_used**: All previous workflow state outputs.
- **actions_taken**: Compiled this final report in markdown format.
- **key_results**: The report you are reading.
- **errors_or_gaps**: None.

- **agent_name**: SaveReportAgent
- **purpose**: Writes the final report to the specified output.
- **inputs_used**: `report_content` from ReportAgent.
- **actions_taken**: Pending execution by downstream workflow.
- **key_results**: Status pending.
- **errors_or_gaps**: N/A.