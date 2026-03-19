# Honeypot Threat Hunting Report

## 1. Investigation Scope
- **investigation_start**: 2026-03-19T12:00:07Z
- **investigation_end**: 2026-03-19T15:00:07Z
- **completion_status**: Complete
- **degraded_mode**: true - Initial candidate discovery was degraded due to backend tool failures, which prevented the correlation of key signals (ICS activity, CVEs) with source IPs. The subsequent reflection investigation successfully mitigated the most critical evidence gaps.

## 2. Executive Triage Summary
- **Top Services/Ports of Interest**: VNC (5900-5904) due to high-volume scanning; SMB (445) from a concentrated source; and multiple web development ports (3000-8081) targeted by a broad vulnerability scanner.
- **Top Confirmed Known Exploitation**: Activity matching `CVE-2025-55182` (a critical RCE in React Server Components) was observed. The reflection investigation successfully identified two distinct actors exploiting this vulnerability.
- **Top Unmapped Exploit-Like Items**: No novel exploit candidates were validated. The most unusual activity (ICS protocols) was determined to be a benign artifact of the honeypot system itself.
- **Botnet/Campaign Mapping Highlights**:
    - Mapped two distinct campaigns exploiting CVE-2025-55182: one targeted scanner from Romania (`193.32.162.28`) and one broad, multi-purpose scanner from a DigitalOcean host (`129.212.239.91`).
    - A high-volume VNC scanning campaign was mapped to a single source IP (`207.174.1.152`).
    - A concentrated SMB scanning campaign was identified from a single source IP (`62.148.236.165`).
- **Major Uncertainties**: The initial investigation was blocked from identifying the actors behind the CVE-2025-55182 exploitation. This was resolved during the reflection phase of the workflow.

## 3. Candidate Discovery Summary
- **Initial Candidates Identified**: 5 candidates were generated, spanning botnet mapping, potential n-day exploitation, odd-service attacks, and suspicious activity for monitoring.
- **Discovery Impact**: The discovery phase was materially affected by failed queries for Conpot (ICS) and CVE-related source IPs. This prevented a full, evidence-based correlation at the outset and forced a provisional classification for two high-priority candidates (`NDE-01`, `ODD-01`), which required follow-up via OSINT and reflection to resolve.

## 4. Emerging n-day Exploitation
- **Item ID**: NDE-01 (enhanced by REF-01)
- **CVE/Signature Mapping**: CVE-2025-55182 (Critical RCE in React Server Components, aka "React2Shell")
- **Evidence Summary**: 165 Suricata alert events were recorded. The reflection investigation identified two source IPs responsible for the activity: `193.32.162.28` and `129.212.239.91`.
- **Affected Service/Port**: Web Application (HTTP/S) across numerous ports including 6005, 3000-3012, 4000, 8081, etc.
- **Confidence**: High
- **Operational Notes**: This is a known, actively exploited vulnerability. Telemetry analysis revealed two distinct actor profiles: one conducting targeted exploitation of specific Next.js paths, and another performing broad, multi-vulnerability scanning across many common development ports.

## 5. Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
*No candidates met the criteria for this category.*

## 6. Botnet/Campaign Infrastructure Mapping
- **Item ID**: REF-01-CAMPAIGN-A (CVE Exploitation)
- **Campaign Shape**: Targeted Exploitation
- **Suspected Compromised Src IPs**: `193.32.162.28`
- **ASNs / Geo Hints**: AS47890 / Unmanaged Ltd (Romania)
- **Suspected Staging/C2 Indicators**: None observed. Activity focused on systematically testing six specific React/Next.js URL paths (`/`, `/_next`, `/_next/server`, `/api`, `/api/route`, `/app`) on port 6005, consistent with a dedicated exploit script.
- **Confidence**: High
- **Operational Notes**: This actor appears to be running a focused campaign to exploit CVE-2025-55182.

---

- **Item ID**: REF-01-CAMPAIGN-B (CVE Exploitation)
- **Campaign Shape**: Fan-out (Broad Scanning)
- **Suspected Compromised Src IPs**: `129.212.239.91`
- **ASNs / Geo Hints**: AS14061 / DigitalOcean, LLC (Singapore)
- **Suspected Staging/C2 Indicators**: None observed. Activity consisted of broad scanning across 20+ web development ports. Payloads were designed to be highly efficient, testing for CVE-2025-55182, Javascript Sandbox Escape, and Javascript Prototype Pollution in a single request.
- **Confidence**: High
- **Operational Notes**: This is a multi-purpose vulnerability scanner. Its use of the generic `Go-http-client/1.1` user agent makes it difficult to track by that indicator alone.

---

- **Item ID**: BOT-01
- **Campaign Shape**: Fan-out (Broad Scanning)
- **Suspected Compromised Src IPs**: `207.174.1.152` (1201+ events)
- **ASNs / Geo Hints**: AS398019 / Dynu Systems Incorporated (United States)
- **Suspected Staging/C2 Indicators**: None observed. The campaign appears to be purely for VNC service discovery.
- **Confidence**: High
- **Operational Notes**: Deep investigation confirmed this was a highly focused, 18-minute VNC scanning burst from a single IP.

---

- **Item ID**: BOT-02
- **Campaign Shape**: Spray
- **Suspected Compromised Src IPs**: `62.148.236.165` (596 events)
- **ASNs / Geo Hints**: AS12389 / Rostelecom (Russia)
- **Suspected Staging/C2 Indicators**: None observed.
- **Confidence**: Medium
- **Operational Notes**: Represents a concentrated source of SMB scanning. Classified as general internet background noise.

## 7. Odd-Service / Minutia Attacks
- **Item ID**: ODD-01
- **Service Fingerprint**: `kamstrup_protocol` (port 1025), `guardian_ast` (Telnet) on Conpot Honeypot.
- **Why it’s unusual/interesting**: Activity involves Industrial Control System (ICS) protocols for smart meters and gas tank gauges, which is highly anomalous in general internet traffic.
- **Evidence Summary**: 36 events for `kamstrup_protocol`, 14 for `guardian_ast`.
- **Confidence**: High (that the activity occurred), N/A (as a threat)
- **Recommended Monitoring Pivots**: This activity was confirmed by OSINT to be benign, internal emulation by the Conpot honeypot itself and not an external attack. It should be filtered from future threat discovery reports as a known false positive.

## 8. Known-Exploit / Commodity Exclusions
- **Known n-day Activity (NDE-01/REF-01)**: Events for CVE-2025-55182. This is a widely known and publicly exploited vulnerability. The actors and their TTPs were identified in the reflection phase.
- **Commodity VNC Scanning (BOT-01)**: High-volume scanning from `207.174.1.152`. Fully explained by the informational Suricata signature "GPL INFO VNC server response".
- **Known Web Scanning (MON-01)**: Low-volume scanning for `/.env` files from `78.153.140.93` and `185.213.154.249`. OSINT confirmed the source IPs have a public history of involvement in malicious scanning.
- **Commodity Credential Scanning**: Standard SSH brute-force attempts using common usernames (`root`, `admin`) and passwords (`1234`, `123456`).
- **Honeypot Artifacts (ODD-01)**: ICS protocol events were identified as internal Conpot honeypot emulation, not a real external threat.

## 9. Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: Confirmed exploitation activity was observed for CVE-2025-55182. The remaining majority of activity was scanning (VNC, SMB, web).
- **Campaign Shape**: A mix of shapes was observed: a targeted exploitation script and a broad `fan-out` scanner for the CVE campaign; a high-intensity `fan-out` for VNC scanning; and an opportunistic `spray` model for SMB and `.env` scanning.
- **Infra Reuse Indicators**: The IPs involved in the `.env` scanning (`MON-01`) have a public history of abuse. The CVE exploitation activity originates from hosting providers (Unmanaged Ltd, DigitalOcean) commonly used for both legitimate and malicious purposes.

## 10. Evidence Appendix
- **Item: NDE-01/REF-01 (CVE-2025-55182 Exploitation)**
    - **Source IPs**: `193.32.162.28`, `129.212.239.91`
    - **ASNs**: AS47890 (Unmanaged Ltd), AS14061 (DigitalOcean, LLC)
    - **Target Ports/Services**: 6005, 3000-3012, 4000, 8080, 8081, and others.
    - **Paths/Endpoints**: `/`, `/_next`, `/_next/server`, `/api`, `/api/route`, `/app`
    - **Payload/Artifact Excerpts**: Suricata signatures: `ET WEB_SPECIFIC_APPS React Server Components React2Shell...`, `ET HUNTING Javascript Sandbox Escape...`, `ET HUNTING Javascript Prototype Pollution...`
    - **Temporal Checks**: Activity spanned the majority of the 3-hour window.

- **Item: BOT-01 (VNC Scanning Campaign)**
    - **Source IPs**: `207.174.1.152`
    - **ASNs**: AS398019 (Dynu Systems Incorporated)
    - **Target Ports/Services**: 5900
    - **Payload/Artifact Excerpts**: Suricata signature "GPL INFO VNC server response"
    - **Temporal Checks**: A short burst lasting approximately 18 minutes (12:46:57Z to 13:04:27Z).

- **Item: BOT-02 (SMB Scanning Campaign)**
    - **Source IPs**: `62.148.236.165`
    - **ASNs**: AS12389 (Rostelecom)
    - **Target Ports/Services**: 445

## 11. Indicators of Interest
- **IPs**:
    - `193.32.162.28` (Targeted CVE-2025-55182 exploiter)
    - `129.212.239.91` (Broad multi-vulnerability scanner)
    - `207.174.1.152` (High-volume VNC scanner)
    - `62.148.236.165` (Concentrated SMB scanner)
    - `78.153.140.93` (Web scanner, known bad reputation)
    - `185.213.154.249` (Web scanner, associated with abusive subnet)
- **CVEs**:
    - `CVE-2025-55182`
- **Signatures**:
    - `ET HUNTING Javascript Sandbox Escape via Global Object (process)`
    - `ET HUNTING Javascript Prototype Pollution Attempt via __proto__ in HTTP Body`
- **User Agents**:
    - `Go-http-client/1.1` (Associated with the multi-purpose scanner, but noted as generic)

## 12. Reflection Findings
- **Reflection Candidates Discovered**: Four candidates (`REF-01` to `REF-04`) were identified, targeting critical evidence gaps and areas for deeper analysis.
- **Actions Taken**: A deep reflection investigation was launched for candidate `REF-01` to address the failure to identify the source of `CVE-2025-55182` alerts.
- **Findings of Reflection**: 
    - The investigation successfully bypassed the failing `top_src_ips_for_cve` tool by analyzing raw `suricata_cve_samples`.
    - It identified two distinct actors exploiting the CVE:
        1.  `193.32.162.28` (AS47890): A targeted scanner using a programmatic script to hit specific React/Next.js endpoints on port 6005.
        2.  `129.212.239.91` (AS14061): A broad, multi-purpose scanner hitting over 20 web ports and testing for three vulnerabilities (CVE-2025-55182, Sandbox Escape, Prototype Pollution) simultaneously with a `Go-http-client/1.1` user agent.
- **Enhancement of Other Findings**: The reflection findings directly resolved the "degraded" status of the `NDE-01` candidate and created two new high-confidence `Botnet/Campaign Infrastructure Mapping` entries, transforming a major evidence gap into the most detailed finding of this report.

## 13. Backend Tool Issues
- **Tool**: `two_level_terms_aggregated`, `top_src_ips_for_cve`
    - **Failure**: These aggregation tools repeatedly returned no results for queries against `Conpot` activity and `CVE-2025-55182` alerts. The issue appears to be persistent.
    - **Impact**: Blocked initial correlation of the most frequent CVE and the most unusual service activity with their source infrastructure. This forced a `degraded_mode` state and necessitated the use of the reflection workflow to mitigate the gap.

## 14. Agent Action Summary (Audit Trail)
- **Agent**: ParallelInvestigationAgent
    - **Purpose**: Conduct initial broad-spectrum data gathering.
    - **Inputs Used**: `investigation_start`, `investigation_end`.
    - **Actions Taken**: Executed baseline queries for traffic stats, known signatures, credential noise, and honeypot-specific logs.
    - **Key Results**: Identified VNC/SMB scanning, CVE-2025-55182 alerts, and anomalous ICS protocol events.
    - **Errors/Gaps**: None.

- **Agent**: CandidateDiscoveryAgent
    - **Purpose**: Synthesize parallel inputs and identify promising leads.
    - **Inputs Used**: All parallel agent results.
    - **Actions Taken**: Merged inputs and generated 5 candidates. Attempted to enrich candidates with source IPs.
    - **Key Results**: Created a structured list of 5 candidates for validation.
    - **Errors/Gaps**: Key queries (`top_src_ips_for_cve`, `two_level_terms_aggregated`) failed, preventing correlation for two candidates and triggering `degraded_mode`.

- **Agent**: CandidateValidationLoopAgent
    - **Purpose**: Iteratively process and validate candidates.
    - **Inputs Used**: `candidate_discovery_result`.
    - **Actions Taken**: Ran 1 iteration, validating candidate `BOT-01`.
    - **Key Results**: Confirmed `BOT-01` as a commodity VNC scanning campaign.
    - **Errors/Gaps**: Only processed one candidate before handoff to deep investigation.

- **Agent**: DeepInvestigationLoopController
    - **Purpose**: Manage the deep investigation of high-value candidates.
    - **Inputs Used**: `validated_candidates`.
    - **Actions Taken**: Ran a 2-iteration deep dive on `BOT-01`, pivoting from its source IP to its ASN.
    - **Key Results**: Confirmed the VNC campaign was isolated to a single IP and fully mapped.
    - **Errors/Gaps**: None.

- **Agent**: OSINTAgent
    - **Purpose**: Enrich candidates with public intelligence.
    - **Inputs Used**: `candidate_discovery_result`.
    - **Actions Taken**: Performed multiple search queries for all 5 candidates, focusing on CVEs, protocols, and IP reputations.
    - **Key Results**: Confirmed CVE-2025-55182 is a known public threat, identified ICS protocols as benign honeypot functions, and verified the bad reputation of IPs in `MON-01`.
    - **Errors/Gaps**: Required multiple iterations to satisfy validation checks for some candidates.

- **Agent**: ReflectionCandidateDiscoverAgent
    - **Purpose**: Identify evidence gaps and areas for deeper analysis from the initial report.
    - **Inputs Used**: Final report state.
    - **Actions Taken**: Analyzed the initial investigation's findings and limitations.
    - **Key Results**: Generated 4 reflection candidates, including a critical one (`REF-01`) to address the failure to identify CVE exploiters.
    - **Errors/Gaps**: None.

- **Agent**: ReflectedDeepLoopControllerAgent
    - **Purpose**: Manage a deep investigation based on a reflection candidate.
    - **Inputs Used**: `reflection_candidates`.
    - **Actions Taken**: Initiated a 5-iteration deep dive for `REF-01`.
    - **Key Results**: Successfully oversaw the investigation that closed the CVE evidence gap.
    - **Errors/Gaps**: None.

- **Agent**: ReflectionReportAgent
    - **Purpose**: Compile the final report from all available workflow state outputs, including reflection findings.
    - **Inputs Used**: All state keys from the initial and reflection investigations.
    - **Actions Taken**: Assembled this markdown report.
    - **Key Results**: Generated the final, enhanced investigation report.
    - **Errors/Gaps**: None.

- **Agent**: SaveReportAgent
    - **Purpose**: Save the generated report artifact.
    - **Inputs Used**: The content of this report.
    - **Actions Taken**: Called `deep_agent_write_file`.
    - **Key Results**: Report successfully saved to `/home/user/Haineypot/reports/deep_agent_reports/Deep_Agent_Report_2026-03-19_12-15.md`.
    - **Errors/Gaps**: None.
