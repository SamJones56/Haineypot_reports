# Investigation Report: Honeypot Threat Analysis (2026-03-10T03:00:05Z to 2026-03-10T06:00:05Z)

## 1) Investigation Scope
- **investigation_start**: 2026-03-10T03:00:05Z
- **investigation_end**: 2026-03-10T06:00:05Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true. A data query for Conpot (ICS honeypot) activity failed, preventing source IP correlation for observed Kamstrup protocol interactions. 

## 2) Executive Triage Summary
- **Top Services/Ports of Interest**:
    - **VNC (5900-5904)**: Widespread scanning and exploitation of a known vulnerability (CVE-2006-2369).
    - **SMB (445)**: High-volume scanning activity.
    - **HTTP (80)**: Probing for web application vulnerabilities, including command injection and file inclusion.
    - **Minecraft (25565)**: Anomalous scanning activity from sources with a spoofed or custom OS fingerprint ("Nintendo 3DS").
    - **ICS/SCADA (kamstrup_protocol)**: Activity targeting industrial control systems was observed but could not be fully analyzed due to query failures.
- **Top Confirmed Known Exploitation**: Commodity scanning and exploitation of VNC (CVE-2006-2369) was the most prevalent known activity.
- **Top Unmapped Exploit-like Items**: A sophisticated web scanner was identified probing for command injection and LFI vulnerabilities. While the techniques are known, the tool itself is unmapped.
- **Botnet/Campaign Mapping Highlights**: 
    - A large-scale VNC scanning campaign originating from ASN 16347 (ADISTA SAS).
    - A coordinated, multi-IP campaign targeting Minecraft servers using an anomalous OS fingerprint.
- **Major Uncertainties**: The actors and infrastructure behind the Kamstrup ICS protocol activity remain unknown due to a backend tool failure.

## 3) Candidate Discovery Summary
- The discovery process identified two primary areas of interest from a total of 18,404 attacks:
    1.  **Web vulnerability scanning (Tanner-CmdInject-20260310-01)**: Activity on port 80 involving URIs indicative of command injection (`/$(pwd)/*`).
    2.  **Anomalous Game Server Scanning (P0f-Nintendo-Minecraft-20260310-01)**: Activity on port 25565 (Minecraft) from clients fingerprinted as "Nintendo 3DS".
- **Material Gaps**: A query failure (`two_level_terms_aggregated` for Conpot) prevented the discovery of candidates related to observed `kamstrup_protocol` activity.

## 4) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
*No candidates met the criteria for Novel or Potential Zero-Day classification after validation and OSINT analysis. Initial candidate `Tanner-CmdInject-20260310-01` was downgraded as its methods are publicly known, and it is now classified under Botnet/Campaign Infrastructure.* 

## 5) Botnet/Campaign Infrastructure Mapping

### Item: Tanner-CmdInject-20260310-01 (Web Vulnerability Scanner)
- **item_id**: Tanner-CmdInject-20260310-01
- **campaign_shape**: fan-out (one source IP, many malicious payloads)
- **suspected_compromised_src_ips**: 185.177.72.51 (2,024 events)
- **ASNs / geo hints**: ASN 211590 (Bucklog SARL, France)
- **suspected_staging indicators**: The URI paths themselves are the primary indicators, suggesting a vulnerability scanner tool. Examples include `"/$(pwd)/*.auto.tfvars"`, `"function readOurFile(relPath = '.test')"`, and `"/libhtp::request_uri_not_seen"`.
- **confidence**: High
- **operational notes**: This IP is running a sophisticated but generic web vulnerability scanner. While the tool is not identified, its techniques (command injection, LFI) are well-established. Signature-based detection should be developed for the unique payloads observed.

### Item: VNC-Scan-20260310-01 (Commodity VNC Exploitation)
- **item_id**: VNC-Scan-20260310-01
- **related_candidate_id(s)**: N/A (Derived from known signals)
- **campaign_shape**: spray
- **suspected_compromised_src_ips**: 79.98.102.166 (2,572 events) and others.
- **ASNs / geo hints**: ASN 16347 (ADISTA SAS)
- **suspected_staging indicators**: N/A
- **confidence**: High
- **operational notes**: Standard, high-volume scanning and exploitation campaign for CVE-2006-2369. This is commodity background noise.

## 6) Odd-Service / Minutia Attacks

### Item: P0f-Nintendo-Minecraft-20260310-01
- **service_fingerprint**: Port 25565/TCP (Minecraft) with a p0f OS fingerprint of "Nintendo 3DS".
- **why it’s unusual/interesting**: The client OS fingerprint is highly anomalous. OSINT confirms the Nintendo 3DS does not host Minecraft servers, indicating the fingerprint is either spoofed or belongs to a custom, undocumented scanning tool.
- **evidence summary**: 7 events observed from 4 different source IPs across 2 ASNs, all targeting port 25565 and fingerprinted as "Nintendo 3DS".
- **confidence**: High
- **recommended monitoring pivots**: Track connections to port 25565 from clients with this p0f fingerprint. Attempt to capture full payloads to determine attacker intent.

## 7) Known-Exploit / Commodity Exclusions
- **VNC Exploitation (CVE-2006-2369)**: Excluded due to being well-known, dated, and high-volume commodity activity. Evidenced by 510 `ET EXPLOIT VNC Server Not Requiring Authentication` alerts.
- **Credential Noise**: Standard brute-force attempts using common usernames (`root`, `admin`, `user`) and passwords (`123456`, `password`), seen across many IPs.
- **General Scanning**: High-volume port scanning activity, such as the 1,332 events for `ET SCAN MS Terminal Server Traffic on Non-standard Port`.

## 8) Infrastructure & Behavioral Classification
- **exploitation vs scanning**: The investigation identified both active exploitation (VNC CVE-2006-2369) and intelligence-gathering scanners (Tanner-CmdInject, P0f-Nintendo-Minecraft).
- **campaign_shape**: Activity included broad `spray` campaigns (VNC, Minecraft) and targeted `fan-out` probing from a single IP (Tanner).
- **odd-service fingerprints**: The most notable finding was the `p0f:Nintendo 3DS` on port 25565, indicating custom tooling.

## 9) Evidence Appendix

### Tanner-CmdInject-20260310-01
- **source IPs**: 185.177.72.51 (2,024 events)
- **ASNs**: 211590 (Bucklog SARL)
- **target ports/services**: 80 (HTTP)
- **payload/artifact excerpts**: 
    - `/$(pwd)/*.auto.tfvars`
    - `/libhtp::request_uri_not_seen`
    - `function readOurFile(relPath = ".test")`
    - `"0.0.0.0", () =>`
- **temporal checks**: unavailable

### P0f-Nintendo-Minecraft-20260310-01
- **source IPs**: 51.15.34.47, 176.65.148.185, 176.65.134.24, 176.65.149.219
- **ASNs**: 12876 (Scaleway S.a.s.), 51396 (Pfcloud UG)
- **target ports/services**: 25565 (Minecraft)
- **payload/artifact excerpts**: p0f OS Fingerprint: `Nintendo 3DS`. (Note: TCP payload content is an evidence gap).
- **temporal checks**: unavailable

### VNC-Scan-20260310-01
- **source IPs**: 79.98.102.166 (2,572 events)
- **ASNs**: 16347 (ADISTA SAS)
- **target ports/services**: 5901, 5902, 5903, 5904 etc.
- **payload/artifact excerpts**: Suricata Signature: `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)`
- **temporal checks**: unavailable

## 10) Indicators of Interest
- **IPs**:
    - `185.177.72.51` (Web vulnerability scanner)
    - `51.15.34.47`, `176.65.148.185` (Minecraft scanners with spoofed fingerprint)
- **ASNs**: 
    - `211590` (Bucklog SARL) - Monitor for web scanning.
- **Payloads / Fingerprints**:
    - URI contains `$(pwd)`
    - URI contains `readOurFile`
    - URI contains `libhtp::request_uri_not_seen`
    - p0f OS Fingerprint `Nintendo 3DS` on TCP/25565.

## 11) Backend Tool Issues
- **Tool Failure**: `two_level_terms_aggregated` in `CandidateDiscoveryAgent`.
- **Affected Validation**: The query was intended to correlate source IPs with Conpot honeypot events. Its failure prevented the identification of actors targeting ICS systems using the `kamstrup_protocol`.
- **Weakened Conclusions**: Any conclusions about the campaign targeting ICS infrastructure are blocked. We can only confirm the protocol was used, but not by whom or as part of what campaign.

## 12) Agent Action Summary (Audit Trail)

- **ParallelInvestigationAgent**: 
    - **Purpose**: To run initial data gathering agents in parallel.
    - **Inputs_used**: `investigation_start`, `investigation_end`.
    - **Actions_taken**: Executed `BaselineAgent`, `KnownSignalAgent`, `CredentialNoiseAgent`, and `HoneypotSpecificAgent`.
    - **Key_results**: Produced baseline statistics, known threat signatures (VNC, RDP), credential stuffing patterns, and honeypot-specific interactions (Kamstrup, Tanner).
    - **Errors_or_gaps**: None.

- **CandidateDiscoveryAgent**:
    - **Purpose**: To identify potential novel threats from the initial data.
    - **Inputs_used**: Outputs from all parallel agents.
    - **Actions_taken**: Aggregated Tanner paths, searched for unusual p0f OS fingerprints.
    - **Key_results**: Identified two candidates: `Tanner-CmdInject-20260310-01` and `P0f-Nintendo-Minecraft-20260310-01`.
    - **Errors_or_gaps**: One query `two_level_terms_aggregated` failed for Conpot data, creating an evidence gap around ICS-targeting activity.

- **CandidateValidationLoopAgent**:
    - **Purpose**: To iterate through and manage the validation of discovered candidates.
    - **Inputs_used**: Candidate list from `CandidateDiscoveryAgent`.
    - **Actions_taken**: Managed a validation loop for 2 iterations.
    - **Key_results**: Processed 2 of 2 candidates (`Tanner-CmdInject-20260310-01`, `P0f-Nintendo-Minecraft-20260310-01`) and exited normally.
    - **Errors_or_gaps**: None.

- **OSINTAgent**:
    - **Purpose**: To enrich validated candidates with open-source intelligence.
    - **Inputs_used**: Validated candidate data.
    - **Actions_taken**: Performed web searches for techniques, tools, and fingerprints related to the candidates.
    - **Key_results**: 
        - Confirmed techniques used by `Tanner-CmdInject` are publicly known, reducing its novelty.
        - Confirmed the `P0f-Nintendo-Minecraft` activity is anomalous and not from legitimate devices, increasing its interest.
    - **Errors_or_gaps**: Inconclusive search results for tools that spoof the "Nintendo 3DS" p0f fingerprint.

- **ReportAgent** (self):
    - **Purpose**: To compile the final report from all workflow state outputs.
    - **Inputs_used**: All preceding agent outputs.
    - **Actions_taken**: Assembled this markdown report.
    - **Key_results**: Report generated.
    - **Errors_or_gaps**: Noted degraded mode due to upstream query failure.

- **SaveReportAgent**:
    - **Purpose**: To save the final report to the designated storage.
    - **Inputs_used**: Final report content.
    - **Actions_taken**: Will call `default_write_file`.
    - **Key_results**: Pending.
    - **Errors_or_gaps**: Pending.

