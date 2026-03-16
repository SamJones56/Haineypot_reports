# Honeypot Threat Intelligence Report

## 1) Investigation Scope

*   **investigation_start**: 2026-03-08T18:00:07Z
*   **investigation_end**: 2026-03-08T21:00:07Z
*   **completion_status**: Complete
*   **degraded_mode**: true
    *   **Reason**: Evidence gaps in VNC campaign source IP attribution (Suricata alerts recorded internal IPs) and the subsequent misassociation of unrelated external IPs in the initial candidate discovery for this campaign.

## 2) Executive Triage Summary

*   **High-Volume Commodity Scanning**: A significant volume (16,758 total attacks) dominated by commodity scanning and credential stuffing.
*   **VNC Exploitation (CVE-2006-2369)**: Widespread attempts to exploit VNC authentication bypass (CVE-2006-2369) were observed across standard and non-standard ports. Direct external source IPs for this specific campaign could not be fully attributed due to internal logging.
*   **SMB Scanning Campaign**: A distinct, high-volume SMB scanning campaign (port 445) was identified, originating primarily from a single IP (103.75.60.46) within AS142448 (INSPIREIT NETWORK SOLUTIONS PRIVATE LIMITED) in India.
*   **Credential Stuffing**: Ongoing brute-force attempts targeting common services like SSH, using typical usernames (`root`, `admin`) and weak passwords.
*   **Odd Service Activity**: A single instance of a TLS Client Hello being sent to a non-encrypted Redis service was noted, indicating a protocol mismatch, likely from a misconfigured scanner.
*   **Emerging N-day Exploits**: Low-volume detections for several recent CVEs (CVE-2025-55182, CVE-2024-38816, CVE-2024-14007, CVE-2021-3449) were observed, warranting continued monitoring.
*   **Infrastructure Attribution Gaps**: The inability to directly map external source IPs to the VNC exploitation alerts due to internal IP logging in Suricata hinders full campaign infrastructure analysis for this specific threat.

## 3) Candidate Discovery Summary

The workflow processed 16,758 total attacks within the 3-hour window.
*   **Top Attacker Countries**: United States (5381), India (3114), Romania (972).
*   **Top Attacker IPs**: 103.75.60.46 (1889), 136.114.97.84 (936), 46.19.137.194 (453).
*   **Top Attacker ASNs**: AS14061 (DigitalOcean, LLC - 3962), AS142448 (INSPIREIT NETWORK SOLUTIONS PRIVATE LIMITED - 1889).
*   **Top Target Ports**: VNC (5902, 5903, 5904), SMB (445), SSH (22).
*   **Top Known Signals**: GPL INFO VNC server response (21921), ET EXPLOIT VNC Server Not Requiring Authentication (case 2) (1834, mapped to CVE-2006-2369).
*   **Top Credential Noise**: Usernames `root` (216), `admin` (63); Passwords `345gs5662d34` (45), `123456` (44).
*   **Honeypot Interactions**: Minimal Adbhoney reconnaissance, Tanner probes for common web paths (/, /.env, /boaform), and one Redis TLS protocol mismatch. No Conpot activity.
*   **Identified Candidates**:
    *   1 Botnet/Campaign Infrastructure Mapping candidate (VNC exploitation, BCM-1).
    *   4 Emerging N-day Exploitation candidates (low count CVEs).
    *   1 Odd-Service / Minutia Attack candidate (Redis TLS mismatch, OSM-1).
    *   2 Known-Exploit / Commodity Exclusion candidates (VNC exploitation, Boaform probe).
    *   1 Suspicious Unmapped Activity to Monitor candidate (Boaform probe, SUM-1).
*   **Discovery Gaps**: The initial candidate discovery for VNC exploitation incorrectly associated external source IPs with the campaign due to internal IP logging in Suricata alerts for CVE-2006-2369. This required re-evaluation during validation.

## 4) Emerging n-day Exploitation

*   **CVE**: CVE-2025-55182
    *   **Evidence Summary**: 117 events detected.
    *   **Affected Service/Port**: Not specified in current data.
    *   **Confidence**: Low (due to very low event count and lack of specific context beyond CVE ID).
    *   **Operational Notes**: Monitor for increased activity or associated artifacts.
*   **CVE**: CVE-2024-38816
    *   **Evidence Summary**: 10 events detected.
    *   **Affected Service/Port**: Not specified in current data.
    *   **Confidence**: Low (due to very low event count).
    *   **Operational Notes**: Monitor for increased activity.
*   **CVE**: CVE-2024-14007
    *   **Evidence Summary**: 7 events detected.
    *   **Affected Service/Port**: Not specified in current data.
    *   **Confidence**: Low (due to very low event count).
    *   **Operational Notes**: Monitor for increased activity.
*   **CVE**: CVE-2021-3449
    *   **Evidence Summary**: 6 events detected.
    *   **Affected Service/Port**: Not specified in current data.
    *   **Confidence**: Low (due to very low event count and older CVE).
    *   **Operational Notes**: Monitor for increased activity.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)

None identified. All exploit-like behavior was successfully mapped to known CVEs, signatures, or commodity activity.

## 6) Botnet/Campaign Infrastructure Mapping

### Item: BCM-1 (VNC Exploitation Campaign)

*   **item_id**: BCM-1
*   **campaign_shape**: Spray
*   **suspected_compromised_src_ips**: Unknown. Suricata alerts for CVE-2006-2369 recorded internal source IP (10.17.0.5), preventing direct external attribution.
*   **ASNs / geo hints**: Unknown.
*   **suspected_staging indicators**: None.
*   **suspected_c2 indicators**: None.
*   **confidence**: High (in identification of exploitation, but low for external source attribution).
*   **operational_notes**: Investigate logging configuration to capture external source IPs for Suricata alerts. Continue monitoring VNC-related ports for unusual patterns.

### Item: DI-SMB-1 (Large-scale SMB Scanning Campaign)

*   **item_id**: DI-SMB-1 (Derived from deep investigation)
*   **campaign_shape**: Spray (scanning)
*   **suspected_compromised_src_ips**: 103.75.60.46 (1889 flow events, 15271 total events observed by honeypots)
*   **ASNs / geo hints**: AS142448 (INSPIREIT NETWORK SOLUTIONS PRIVATE LIMITED), India
*   **suspected_staging indicators**: None.
*   **suspected_c2 indicators**: None.
*   **confidence**: High
*   **operational_notes**: Block IP 103.75.60.46. Monitor for other IPs from AS142448 engaging in similar SMB scanning behavior.

## 7) Odd-Service / Minutia Attacks

*   **service_fingerprint**: Redis (default port 6379 implied), TCP protocol
*   **why it’s unusual/interesting**: A single instance of a TLS Client Hello (`\x16\x03\x03\x01...`) was observed attempting to communicate with the Redis service. Redis, by default, expects plaintext connections unless explicitly configured for TLS. This indicates a protocol mismatch.
*   **evidence_summary**: 1 event (Redis input log consistent with TLS Client Hello).
*   **confidence**: High
*   **recommended_monitoring_pivots**: Monitor Redis honeypot for an increase in TLS handshake attempts or variations in these inputs. This is likely a misconfigured scanner rather than a targeted exploit.

## 8) Known-Exploit / Commodity Exclusions

*   **Commodity VNC Exploit Scanning**: High volume of alerts (1834 for `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)` and 21921 for `GPL INFO VNC server response`) associated with CVE-2006-2369. This is a well-known, old vulnerability consistent with automated, widespread scanning attempts.
*   **Common Web Exploit Probe**: A single, unrepeated request for `/boaform/admin/formLogin?username=user&psd=user` was observed via the Tanner honeypot. This is a characteristic probe for known vulnerabilities in Boa web servers on embedded devices, often seen as opportunistic scanning noise.
*   **Credential Noise/Brute Force**: Extensive brute-force activity primarily targeting SSH (port 22) and VNC-related ports, using common usernames (`root`, `admin`, `user`) and weak passwords (`123456`, `password`, `12345678`). This is typical, low-value scanning behavior.
*   **MS Terminal Server Scanning**: 790 alerts for `ET SCAN MS Terminal Server Traffic on Non-standard Port`, indicating generic scanning for RDP services on unexpected ports.

## 9) Infrastructure & Behavioral Classification

*   **VNC Exploitation (CVE-2006-2369)**: Large-scale, spray-type scanning and exploitation attempts. Due to internal logging, the external source infrastructure could not be directly mapped, but the activity pattern indicates automated, opportunistic campaigns targeting VNC services.
*   **SMB Scanning**: A distinct, high-volume spray scanning campaign originating from a single compromised source IP (103.75.60.46) within AS142448 (INSPIREIT NETWORK SOLUTIONS PRIVATE LIMITED), exclusively targeting TCP/445. No further infrastructure reuse indicators were found beyond this single IP for this campaign.
*   **Credential Stuffing**: Ubiquitous scanning with commodity tools, exhibiting a spray pattern across various common ports (e.g., SSH, telnet) and relying on basic dictionary attacks.
*   **Web Probing**: Low-volume, opportunistic scanning for known web application vulnerabilities and common sensitive files (e.g., /.env, /boaform/admin/formLogin), often associated with general internet noise.
*   **Odd-Service Fingerprints**: A single instance of a TLS Client Hello to a plaintext Redis service, likely a client-side misconfiguration rather than a malicious exploit.

## 10) Evidence Appendix

### VNC Exploitation Campaign (BCM-1)

*   **Source IPs**: Unknown (Suricata logs showed internal IP 10.17.0.5).
*   **ASNs**: Unknown (for the VNC-specific campaign).
*   **Target Ports/Services**: VNC (TCP 5900-5911) and various non-standard high ports (e.g., 3666, 10045, 24890, 34662).
*   **Paths/Endpoints**: VNC protocol negotiation leading to authentication bypass attempts.
*   **Payload/Artifact Excerpts**:
    *   `GPL INFO VNC server response`
    *   `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)`
*   **Staging Indicators**: None.
*   **Temporal Checks**: Consistent with activity throughout the 3-hour investigation window.

### SMB Scanning Campaign (DI-SMB-1)

*   **Source IPs**: 103.75.60.46 (1889 Dionaea events, >10000 flow events).
*   **ASNs**: AS142448 (INSPIREIT NETWORK SOLUTIONS PRIVATE LIMITED) in India.
*   **Target Ports/Services**: SMB (TCP 445).
*   **Paths/Endpoints**: SMB protocol negotiation.
*   **Payload/Artifact Excerpts**: Primarily flow records, no specific Suricata alert signatures triggered, indicating reconnaissance-level activity.
*   **Staging Indicators**: None.
*   **Temporal Checks**: Active from 2026-03-08T20:33:04Z to 2026-03-08T20:59:46Z.

## 11) Indicators of Interest

*   **IPs**:
    *   `103.75.60.46` (Source for high-volume SMB scanning)
*   **ASNs**:
    *   `AS142448` (INSPIREIT NETWORK SOLUTIONS PRIVATE LIMITED) (Associated with 103.75.60.46 SMB scanning)
*   **Ports**:
    *   `TCP/445` (SMB)
    *   `TCP/5900-5911` (VNC)
*   **Paths/Endpoints**:
    *   `/boaform/admin/formLogin?username=user&psd=user` (Common web exploit probe)
    *   `/.env` (Common web enumeration path)
*   **CVEs/Signatures**:
    *   `CVE-2006-2369` (VNC Authentication Bypass)
    *   `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)`
    *   `GPL INFO VNC server response`
    *   `ET SCAN MS Terminal Server Traffic on Non-standard Port`

## 12) Backend Tool Issues

*   **CandidateValidationAgent.get_cve**: Failed for candidate BCM-1 because mandatory parameters (`size`, `gte_time_stamp`, `lte_time_stamp`) were missing. This did not block validation, as `AgentTool(search)` and signature samples confirmed the CVE and its characteristics.
*   **CandidateValidationAgent.suricata_signature_samples**: Identified that all Suricata alerts for CVE-2006-2369 (VNC exploitation) recorded an internal source IP (`10.17.0.5`). This prevented direct attribution of external attacker IPs to the VNC campaign, leading to an "Unknown" classification for source infrastructure. This significantly weakened the infrastructure mapping aspect of the BCM-1 candidate.
*   **OSINTAgent**: Explicitly did not perform OSINT for low-count emerging N-day CVEs (CVE-2025-55182, CVE-2024-38816, CVE-2024-14007, CVE-2021-3449) and already mapped known exclusions, as per workflow guidelines. This means specific public context for these low-volume CVEs was not gathered, leading to low confidence ratings in the report.

## 13) Agent Action Summary (Audit Trail)

*   **Agent Name**: BaselineAgent
    *   **Purpose**: Gathers fundamental statistics and top indicators from raw telemetry.
    *   **Inputs Used**: `investigation_start`, `investigation_end` (via `get_report_time`).
    *   **Actions Taken**: Queried total attacks, top countries, top source IPs, country-to-port mapping, and top ASNs.
    *   **Key Results**: Identified 16758 total attacks, top countries (US, India), top attacker IPs (103.75.60.46), top ASNs (DigitalOcean, INSPIREIT).
    *   **Errors or Gaps**: None.
*   **Agent Name**: KnownSignalAgent
    *   **Purpose**: Identifies known exploitation patterns and alerts within the investigation window.
    *   **Inputs Used**: `investigation_start`, `investigation_end`.
    *   **Actions Taken**: Queried top alert signatures, CVEs, alert categories, and performed keyword searches for "ET" in signatures and "HTTP" in messages.
    *   **Key Results**: Highlighted widespread VNC scanning (CVE-2006-2369, 21921 events), MS Terminal Server scanning (790 events), and several recent low-volume CVEs.
    *   **Errors or Gaps**: None.
*   **Agent Name**: CredentialNoiseAgent
    *   **Purpose**: Characterizes credential-based attacks and broad host enumeration.
    *   **Inputs Used**: `investigation_start`, `investigation_end`.
    *   **Actions Taken**: Queried top usernames, top passwords, and p0f OS distribution.
    *   **Key Results**: Identified common brute-force usernames (`root`, `admin`) and passwords (`123456`), and the prevalent OS fingerprints (Windows NT, Linux).
    *   **Errors or Gaps**: None.
*   **Agent Name**: HoneypotSpecificAgent
    *   **Purpose**: Analyzes interactions with various honeypot deployments for specific attack vectors.
    *   **Inputs Used**: `investigation_start`, `investigation_end` (via `get_report_time`).
    *   **Actions Taken**: Queried Redis actions, Adbhoney inputs and malware samples, Conpot inputs and protocols, and Tanner URI paths.
    *   **Key Results**: Noted minimal Adbhoney reconnaissance, Tanner probes for common web paths (/, /.env, /boaform), and a Redis TLS protocol mismatch. No malware samples or Conpot activity.
    *   **Errors or Gaps**: None.
*   **Agent Name**: CandidateDiscoveryAgent
    *   **Purpose**: Consolidates results from parallel agents, identifies potential threats, and classifies them.
    *   **Inputs Used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    *   **Actions Taken**: Merged all parallel outputs. Identified initial candidates for Botnet/Campaign Mapping, Emerging N-day, Odd-Service, Known Exploit Exclusions, and Suspicious Unmapped. Performed initial queries for CVE-2006-2369 source IPs and dest ports.
    *   **Key Results**: Generated a comprehensive triage summary and an initial set of 9 candidates. Explicitly noted an evidence gap regarding CVE-2006-2369 source IPs.
    *   **Errors or Gaps**: None in tool execution, but identified an evidence gap in data correlating external IPs to the VNC CVE.
*   **Agent Name**: CandidateValidationLoopAgent
    *   **Purpose**: Manages the validation process for identified candidates.
    *   **Inputs Used**: Candidates from `CandidateDiscoveryAgent`.
    *   **Actions Taken**: Initialized a queue of 9 candidates. Loaded and validated `BCM-1` (VNC Exploitation Campaign). Performed `search` for CVE details, `suricata_signature_samples` to inspect alerts, and `events_for_src_ip` to verify source IPs for the campaign.
    *   **Key Results**: Validated `BCM-1`, confirming CVE-2006-2369 exploit attempts but found that Suricata alerts recorded internal IPs, disproving initial external IP attribution for this campaign.
    *   **Errors or Gaps**: `get_cve` tool failed due to missing parameters (size, gte_time\_stamp, lte\_time\_stamp). Validation was not blocked, but this indicates a minor tool usage issue.
*   **Agent Name**: DeepInvestigationLoopController
    *   **Purpose**: Pursues high-priority leads in depth to characterize novel threats or campaigns.
    *   **Inputs Used**: `validated_candidates` (specifically, insights from BCM-1 validation), `baseline_result`, `known_signals_result`.
    *   **Actions Taken**: Iteration 1: Started with leads `src_ip:103.75.60.46`, `asn:142448`, `service:smb/445`, `signature:ET SCAN MS Terminal Server Traffic on Non-standard Port`, `cve:CVE-2006-2369`. Explored `src_ip:103.75.60.46` using `first_last_seen_src_ip` and `kibanna_discover_query`. Iteration 2: Explored `asn:142448` using `two_level_terms_aggregated`.
    *   **Key Results**: Confirmed `103.75.60.46` as the sole source of a high-volume, SMB-only scanning campaign within AS142448, active for 26 minutes, with no specific Suricata alerts.
    *   **Errors or Gaps**: None. Exited naturally after 2 consecutive iterations without new leads (stall count 2).
*   **Agent Name**: OSINTAgent
    *   **Purpose**: Enriches validated candidates with external open-source intelligence.
    *   **Inputs Used**: All candidates from Candidate Discovery, specifically focusing on `BCM-1` and `OSM-1` based on search requests.
    *   **Actions Taken**: Performed `search` for "Vulnerability details for CVE-2006-2369 VNC authentication" and "TLS Client Hello to non-encrypted Redis".
    *   **Key Results**: Confirmed public knowledge of CVE-2006-2369 and the Redis TLS protocol mismatch, enhancing confidence in classifications. Determined other low-count CVE candidates and known exclusions did not require further OSINT.
    *   **Errors or Gaps**: None.
*   **Agent Name**: ReportAgent
    *   **Purpose**: Compiles the final report from all workflow state outputs.
    *   **Inputs Used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates` (from CandidateValidationLoopAgent), `deep_investigation_outputs` (from DeepInvestigationLoopController), `osint_validation_result`.
    *   **Actions Taken**: Read all available workflow state outputs and synthesized them into the final markdown report as per specified format and logic.
    *   **Key Results**: Generated this report.
    *   **Errors or Gaps**: None.
*   **Agent Name**: SaveReportAgent
    *   **Purpose**: Saves the final report to persistent storage.
    *   **Inputs Used**: Final markdown report content.
    *   **Actions Taken**: Will write the generated report to a file.
    *   **Key Results**: (Pending tool execution)
    *   **Errors or Gaps**: (Pending tool execution)

