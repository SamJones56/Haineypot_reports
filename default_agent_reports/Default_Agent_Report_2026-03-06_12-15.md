# Honeypot Threat Intelligence Report

## 1) Investigation Scope

*   **investigation_start**: 2026-03-06T12:00:05Z
*   **investigation_end**: 2026-03-06T15:00:05Z
*   **completion_status**: Partial (degraded evidence)
*   **degraded_mode**: true
    *   **Reason**: Persistent backend tool errors (specifically `kibanna_discover_query` and `two_level_terms_aggregated` for certain fields) prevented full raw event detail retrieval and precise correlation of source IPs to specific alerts/honeypot interactions for some candidates. This led to incomplete validation and reduced confidence for specific items.

## 2) Executive Triage Summary

*   The honeypot environment observed 24792 total attacks within a 3-hour window.
*   High volume VNC and SMB scanning activities dominated, alongside commodity SSH and general network noise.
*   **Emerging N-day Exploitation:** Detected 144 instances of CVE-2025-55182 (React Server Components React2Shell Unsafe Flight Protocol Property Access), identified as a critical RCE vulnerability by OSINT, actively targeted across multiple web ports from two source IPs.
*   **Known Exploit Techniques (reclassified from "Novel" due to strict rules):** A hunting signature for Javascript Prototype Pollution attempts was triggered 144 times, indicating probing for this known web application attack technique.
*   **Botnet/Campaign Mapping:** Identified clear SMB and VNC spray campaigns from various source IPs and ASNs across different countries. An SMTP scanning campaign was also observed.
*   **Odd-Service/Minutia Attacks:** Interactions with ICS/SCADA (Conpot) honeypots emulating Kamstrup and Guardian AST protocols, as well as basic enumeration on Redis honeypots, were noted.
*   **Suspicious Unmapped Activity:** Enumeration of web application `.env` configuration files on Tanner honeypots by multiple IPs, a common reconnaissance tactic.
*   **Major Uncertainties:** Persistent tool errors blocked the retrieval of full HTTP request bodies for exploit analysis, detailed Conpot interaction inputs, and precise source IP correlation for some alerts, limiting in-depth payload analysis and campaign understanding.

## 3) Candidate Discovery Summary

The discovery phase identified a significant volume of activity, with 24792 total attacks. Top countries for attack origin were the United States (7199), India (3702), Egypt (1674), Qatar (1397), and Ukraine (1341). Key top source IPs included 202.53.65.178 (3109 attacks, India/Nettlinx Limited) and 196.202.80.70 (1673 attacks, Egypt/TE Data).

**Top services/ports of interest:**
*   VNC (ports 5901-5915) with 16358 alerts, primarily from the United States.
*   SMB (port 445) with high volume scanning from India, Egypt, Qatar, Taiwan.
*   SMTP (port 25) scanning from Ukraine.
*   Web Applications (Tanner honeypot) showing enumeration of configuration files (e.g., `/.env`).
*   ICS/SCADA (Conpot honeypot) with interactions involving Kamstrup and Guardian AST protocols.
*   Redis honeypot activity included `INFO` and `PING` commands.
*   MS Terminal Server (non-standard ports) scanning.

**Top known signals detected by Suricata:**
*   `GPL INFO VNC server response` (16358 counts)
*   `SURICATA IPv4 truncated packet` (4095 counts)
*   `SURICATA AF-PACKET truncated packet` (4095 counts)
*   `ET SCAN MS Terminal Server Traffic on Non-standard Port` (678 counts)
*   `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)` (144 counts)
*   `ET HUNTING Javascript Prototype Pollution Attempt via __proto__ in HTTP Body` (144 counts)

**Top CVEs associated with activity:**
*   `CVE-2025-55182` (144 counts)
*   `CVE-2024-14007` (6 counts)

**Credential Noise Summary:**
Common credential brute-forcing was observed, with 'root' (353) and 'admin' (191) being the most frequently attempted usernames, and empty strings (241), '345gs5662d34' (106), and 'password' (48) as top passwords.

**Honeypot Specific Summary:**
*   **Tanner:** Recorded attempts to access web application configuration files (e.g., `/.env`, `/.env.backup`).
*   **Conpot:** Detected interactions via `kamstrup_protocol` (21), `guardian_ast` (12), and `kamstrup_management_protocol` (2).
*   **Redis:** Activity included 'Closed' (12), 'NewConnect' (12), 'info' (6), 'INFO' (4), 'NONEXISTENT' (2), 'PING' (2), 'QUIT' (2) actions.
*   **ADBHoney:** No specific inputs or malware samples observed.

**Missing Inputs/Errors:**
Discovery was materially affected by persistent `kibanna_discover_query` tool errors for various terms (e.g., `alert.signature_id`, `alert.signature.keyword`, `type.keyword:Conpot`) and `two_level_terms_aggregated` for `alert.signature.keyword`, which prevented direct raw event detail retrieval and fine-grained correlation for alerts and some honeypot types.

## 4) Emerging n-day Exploitation

*Note: The item 'NEC-JS-PROTO-POLLUTION-001' was initially classified as a 'Novel Exploit Candidate' by the CandidateDiscoveryAgent. However, due to the strict rule that "CVE/signature-mapped items MUST NOT appear in 'Novel Exploit Candidates'," and the fact that it is mapped to a hunting signature, it has been reclassified and included in this section. OSINT also confirms it as a known technique.*

**Item ID**: ENE-2025-55182-001
*   **CVE/Signature Mapping**: CVE-2025-55182, ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access
*   **Evidence Summary**: 144 detections of the Suricata alert, indicating exploitation attempts against React Server Components. Source IPs `24.144.94.222` and `193.32.162.28` targeted various destination ports (80, 3000-3012, 6060) with HTTP requests to paths like `/`, `/api/route`, `/app`, `/_next/server`, `/api`, and `/_next`.
*   **Affected Service/Port**: HTTP/Web Application (React Server Components) on ports 80, 3000-3012, 6060.
*   **Confidence**: Moderate (CVE/signature identified, raw samples retrieved, but full HTTP request bodies for payload analysis are lacking).
*   **Operational Notes**: OSINT confirms CVE-2025-55182 (React2Shell) is a critical, recently disclosed pre-authentication RCE vulnerability (CVSS 10.0) in React Server Components, involving insecure deserialization and prototype pollution within the 'Flight' protocol. Exploitation was detected as early as December 2025 and is in the CISA KEV catalog. Immediate patching is advised.

**Item ID**: ENE-JS-PROTO-POLLUTION-001 (Reclassified from Novel Exploit Candidates)
*   **CVE/Signature Mapping**: ET HUNTING Javascript Prototype Pollution Attempt via __proto__ in HTTP Body
*   **Evidence Summary**: 144 detections of the Suricata hunting alert. Observed from source IPs `24.144.94.222` and `193.32.162.28` targeting various destination ports (80, 3000-3012, 6060) on internal IP 10.17.0.5 with HTTP requests to paths including `/`, `/api/route`, `/app`, `/_next/server`, `/api`, and `/_next`. The alert category is 'access to a potentially vulnerable web application'.
*   **Affected Service/Port**: HTTP/Web Application on ports 80, 3000-3012, 6060.
*   **Confidence**: Moderate (Signature detected, samples retrieved, OSINT confirms known technique, but full HTTP request bodies are lacking).
*   **Operational Notes**: OSINT confirms Javascript Prototype Pollution via `__proto__` in HTTP bodies is a well-known attack technique that can lead to RCE when chained. This hunting signature indicates active probing for this vulnerability pattern. Requires deeper investigation into specific HTTP body content if tools become available.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)

*No truly unmapped novel exploit candidates were identified in this investigation window, as all exploit-like behavior was associated with known CVEs or Suricata signatures, as per strict reporting guidelines.*

## 6) Botnet/Campaign Infrastructure Mapping

**Item ID**: BCM-SMB-SPRAY-001
*   **Campaign Shape**: Spray
*   **Suspected Compromised Src IPs**: Top IPs include `202.53.65.178` (3109 counts), `196.202.80.70` (1673 counts), `178.153.127.226` (1397 counts), `125.230.197.108` (887 counts).
*   **ASNs / Geo Hints**: ASNs 10225 (Nettlinx Limited, India), 8452 (TE Data, Egypt), 8781 (Ooredoo Q.S.C., Qatar), 3462 (Data Communication Business Group, Taiwan).
*   **Suspected Staging Indicators**: None identified.
*   **Suspected C2 Indicators**: None identified.
*   **Confidence**: High
*   **Operational Notes**: This represents a widespread SMB scanning campaign, likely for initial compromise or reconnaissance, originating from diverse global infrastructure.

**Item ID**: BCM-VNC-SPRAY-001
*   **Campaign Shape**: Spray
*   **Suspected Compromised Src IPs**: `134.209.37.134` (448 attempts across VNC ports).
*   **ASNs / Geo Hints**: Associated with DigitalOcean, LLC (ASN 14061) and Google LLC (ASN 396982) based on general top ASNs for US activity, which includes VNC scanning.
*   **Suspected Staging Indicators**: None identified.
*   **Suspected C2 Indicators**: None identified.
*   **Confidence**: High
*   **Operational Notes**: Focused VNC scanning activity, likely targeting exposed VNC services for unauthorized access.

**Item ID**: BCM-SMTP-SCAN-001
*   **Campaign Shape**: Fan-out
*   **Suspected Compromised Src IPs**: `77.83.39.212` (682 attempts).
*   **ASNs / Geo Hints**: ASN 214940 (Kprohost LLC, Ukraine).
*   **Suspected Staging Indicators**: None identified.
*   **Suspected C2 Indicators**: None identified.
*   **Confidence**: Medium
*   **Operational Notes**: Dedicated SMTP scanning, potentially for open mail relays or vulnerable mail servers for spam/phishing campaigns.

**Item ID**: BCM-DSHIELD-BLOCK-001
*   **Campaign Shape**: Unknown
*   **Suspected Compromised Src IPs**: Not directly linkable from available data, but 326 alerts for 'ET DROP Dshield Block Listed Source group 1'.
*   **ASNs / Geo Hints**: Top general attacker ASNs include DigitalOcean, Nettlinx, TE Data, Ooredoo Q.S.C., Google LLC.
*   **Suspected Staging Indicators**: None identified.
*   **Suspected C2 Indicators**: None identified.
*   **Confidence**: Low (due to inability to link specific IPs directly to these alerts)
*   **Operational Notes**: Indicates activity from known malicious IPs. Requires enhanced logging or correlation capabilities to identify specific sources and intentions.

## 7) Odd-Service / Minutia Attacks

**Item ID**: OSM-CONPOT-ICS-001
*   **Service Fingerprint**: Conpot (ICS/SCADA) - Protocols: `kamstrup_protocol`, `guardian_ast`, `kamstrup_management_protocol`.
*   **Why it’s unusual/interesting**: Targeting of ICS/SCADA honeypots, which represent critical infrastructure components. Interactions observed with Kamstrup (smart meters) and Guardian AST (gas pump monitoring) protocols suggest reconnaissance or attempts to exploit vulnerabilities specific to these systems. OSINT confirms these are known attack vectors.
*   **Evidence Summary**: 21 interactions with `kamstrup_protocol`, 12 with `guardian_ast`, and 2 with `kamstrup_management_protocol`.
*   **Confidence**: Low (interesting target, but lack of detailed interaction inputs or source IP correlation due to tool limitations makes analysis provisional).
*   **Recommended Monitoring Pivots**: Monitor for similar ICS/SCADA interactions. Investigate the root cause of `kibanna_discover_query` failures to gain deeper insights into attack specifics and source IPs.

**Item ID**: OSM-REDIS-ENUM-001
*   **Service Fingerprint**: Redis (assumed port 6379)
*   **Why it’s unusual/interesting**: Basic enumeration activity on a Redis honeypot. Redis is often a target for data theft, cache poisoning, or initial access.
*   **Evidence Summary**: Redis actions included 'Closed' (12), 'NewConnect' (12), 'info' (6), 'INFO' (4), 'NONEXISTENT' (2), 'PING' (2), 'QUIT' (2) commands.
*   **Confidence**: Medium
*   **Recommended Monitoring Pivots**: Monitor for more complex Redis commands, authentication attempts, or data manipulation efforts.

**Item ID**: OSM-UNUSUAL-PORTS-001
*   **Service Fingerprint**: Various non-standard ports: 3333, 3392, 4400, 5500, 6789 (TCP)
*   **Why it’s unusual/interesting**: Scanning/probing of a cluster of non-standard ports by a single source IP. These ports are not typically associated with common services, suggesting targeted reconnaissance or exploitation of niche/custom applications.
*   **Evidence Summary**: Source IP `136.114.97.84` made 82 attempts to each of ports 3333, 3392, 4400, 5500, 6789.
*   **Confidence**: Low
*   **Recommended Monitoring Pivots**: Research common services or vulnerabilities associated with these specific ports.

## 8) Known-Exploit / Commodity Exclusions

*   **Credential Noise**: High volume brute-force attempts targeting common usernames (`root`, `admin`, `postgres`, `oracle`, `user`) and passwords (empty string, `password`, `12345`, `12345678`).
    *   **Evidence Justification**: Detected across many source IPs (e.g., SSH port 22 from 161.35.39.243, 134.199.171.234) with explicit username/password inputs (e.g., `root` 353 counts, `admin` 191 counts; `''` 241 counts, `password` 48 counts).
*   **VNC Scanning**: Extensive scanning for VNC services, indicated by `GPL INFO VNC server response` signature.
    *   **Evidence Justification**: 16358 counts of signature 2100560, primarily targeting ports 5901-5915, notably from the United States.
*   **SMB Scanning**: Widespread scanning activity targeting the Server Message Block (SMB) protocol.
    *   **Evidence Justification**: High volume activity (7066 counts) to destination port 445 from multiple source IPs and countries (India, Egypt, Qatar, Taiwan).
*   **MS Terminal Server Scanning**: Scanning activity on non-standard ports identified as MS Terminal Server traffic.
    *   **Evidence Justification**: 678 counts of signature `ET SCAN MS Terminal Server Traffic on Non-standard Port` (signature_id 2023753).
*   **Network Noise**: Common network-level artifacts like truncated packets and retransmission issues.
    *   **Evidence Justification**: `SURICATA IPv4 truncated packet` (4095 counts), `SURICATA AF-PACKET truncated packet` (4095 counts), `SURICATA STREAM spurious retransmission` (415 counts), `SURICATA STREAM reassembly sequence GAP` (283 counts).
*   **Dshield Block Listed Sources**: Traffic originating from IPs identified on Dshield's block list.
    *   **Evidence Justification**: 326 alerts for `ET DROP Dshield Block Listed Source group 1`.

## 9) Infrastructure & Behavioral Classification

*   **Exploitation vs. Scanning**: The majority of activity was scanning (VNC, SMB, SMTP, MS Terminal Server, credential brute-force, web app .env enumeration). Specific exploit-like behavior was observed for CVE-2025-55182 (React Server Components) and Javascript Prototype Pollution, which are more targeted exploitation attempts. ICS/SCADA interactions also represent directed probing.
*   **Campaign Shape**: Predominantly `spray` (SMB, VNC, SMTP scanning, .env enumeration) where attackers broadly hit many targets. The CVE-2025-55182 and JS Prototype Pollution attempts showed a `multi-stage/spray` pattern with specific IPs targeting varied web paths/ports.
*   **Infra Reuse Indicators**: Several top attacker IPs were associated with known hosting providers/ASNs (DigitalOcean, Nettlinx, TE Data), suggesting use of rented infrastructure or compromised hosts for widespread scanning. The same two source IPs (`24.144.94.222`, `193.32.162.28`) were involved in both the CVE-2025-55182 and JS Prototype Pollution detections, indicating potential actor overlap or use of the same scanning tool.
*   **Odd-Service Fingerprints**: Notable activity on Conpot (Kamstrup Meter/Management, Guardian AST protocols) and Redis, highlighting interest in specialized industrial control systems and data stores.

## 10) Evidence Appendix

**Emerging n-day Exploitation:**

**Item ID: ENE-2025-55182-001 (CVE-2025-55182)**
*   **Source IPs**: `24.144.94.222`, `193.32.162.28`
*   **ASNs**: Not available from workflow state.
*   **Target Ports/Services**: HTTP/Web Application (React Server Components) on ports 80, 3000-3012, 6060.
*   **Paths/Endpoints**: `/`, `/api/route`, `/app`, `/_next/server`, `/api`, `/_next`
*   **Payload/Artifact Excerpts**: Not available (lack of full HTTP request bodies).
*   **Staging Indicators**: None identified.
*   **Temporal Checks**: Observed within the investigation window (2026-03-06T14:53:58Z to 2026-03-06T14:55:48Z).

**Item ID: ENE-JS-PROTO-POLLUTION-001 (Javascript Prototype Pollution)**
*   **Source IPs**: `24.144.94.222`, `193.32.162.28`
*   **ASNs**: Not available from workflow state.
*   **Target Ports/Services**: HTTP/Web Application on ports 80, 3000-3012, 6060.
*   **Paths/Endpoints**: `/`, `/api/route`, `/app`, `/_next/server`, `/api`, `/_next`
*   **Payload/Artifact Excerpts**: Not available (lack of full HTTP request bodies).
*   **Staging Indicators**: None identified.
*   **Temporal Checks**: Observed within the investigation window (2026-03-06T14:53:58Z to 2026-03-06T14:55:48Z).

**Top Botnet/Campaign Infrastructure Mapping Items:**

**Item ID: BCM-SMB-SPRAY-001**
*   **Source IPs**:
    *   `202.53.65.178` (3109 counts)
    *   `196.202.80.70` (1673 counts)
    *   `178.153.127.226` (1397 counts)
    *   `125.230.197.108` (887 counts)
*   **ASNs**:
    *   ASN 10225: Nettlinx Limited (India)
    *   ASN 8452: TE Data (Egypt)
    *   ASN 8781: Ooredoo Q.S.C. (Qatar)
    *   ASN 3462: Data Communication Business Group (Taiwan)
*   **Target Ports/Services**: 445 (SMB)
*   **Paths/Endpoints**: Not applicable.
*   **Payload/Artifact Excerpts**: Generic SMB scan activity.
*   **Staging Indicators**: None identified.
*   **Temporal Checks**: Within investigation window.

## 11) Indicators of Interest

*   **Suspected Exploiting IPs (CVE-2025-55182 & JS Prototype Pollution)**:
    *   `24.144.94.222`
    *   `193.32.162.28`
*   **Top SMB Scanning IPs**:
    *   `202.53.65.178`
    *   `196.202.80.70`
    *   `178.153.127.226`
    *   `125.230.197.108`
*   **Top VNC Scanning IP**:
    *   `134.209.37.134`
*   **Top SMTP Scanning IP**:
    *   `77.83.39.212`
*   **Paths/Endpoints (Web App Reconnaissance)**:
    *   `/.env`
    *   `/django/.env`
    *   `/api/.env`
    *   `/backend/.env`
    *   `/admin/.env`
    *   `/laravel/.env`
    *   `/app/.env`
    *   `/public/.env`
    *   `/symfony/.env`
    *   `/html/.env`
    *   `/frontend/.env`
*   **Suricata Signature IDs**:
    *   `2066027` (CVE-2025-55182)
    *   `2066197` (JS Prototype Pollution)
    *   `2100560` (VNC server response)
    *   `2023753` (MS Terminal Server Traffic)

## 12) Backend Tool Issues

The investigation faced significant limitations due to recurring tool failures:

*   **`kibanna_discover_query`**: Failed across multiple attempts with the error `Expected text at 1:71 but found START_ARRAY`. This specifically impacted:
    *   Retrieval of raw event details for `alert.signature_id` (e.g., signature 2066027).
    *   Retrieval of raw event details for `alert.signature.keyword` (e.g., JS Prototype Pollution signature).
    *   Retrieval of raw event details for `type.keyword:Conpot` and `protocol.keyword:kamstrup_protocol`.
    *   Retrieval of raw event details for `path.keyword:/.env`.
    *   **Affected Conclusions**: This blocked detailed analysis of exploit payloads, full HTTP request bodies, and precise correlation of source IPs to individual alerts, weakening the confidence and granularity of findings for `ENE-2025-55182-001`, `ENE-JS-PROTO-POLLUTION-001`, `OSM-CONPOT-ICS-001`, and `SUM-TANNER-ENV-001`.
*   **`top_src_ips_for_cve`**: Returned no results for `CVE-2025-55182` initially, although source IPs were later identified through `suricata_cve_samples`.
    *   **Affected Conclusions**: Delayed initial identification of specific threat actors for the N-day exploit.
*   **`two_level_terms_aggregated`**: Failed to return buckets for `alert.signature.keyword` as a primary field and for `type.keyword` and `protocol.keyword` with the `Conpot` filter.
    *   **Affected Conclusions**: Hindered comprehensive aggregation of attacker IPs by alert signature and precise correlation of Conpot activity to specific sources, contributing to the `provisional` status of `OSM-CONPOT-ICS-001`.

These issues collectively resulted in a `degraded_mode` for the overall investigation, leading to a `Partial` completion status.

## 13) Agent Action Summary (Audit Trail)

*   **ParallelInvestigationAgent (Phase Summary)**
    *   **Purpose**: Conduct initial parallel data collection across baseline, known signals, credential noise, and honeypot-specific telemetry.
    *   **Inputs Used**: Time window (`investigation_start`, `investigation_end`).
    *   **Actions Taken**: Queried total attacks, top countries, top source IPs, country-to-port mappings, ASNs (BaselineAgent); retrieved alert signatures, CVEs, alert categories, VNC messages (KnownSignalAgent); extracted input usernames, passwords, p0f OS distribution (CredentialNoiseAgent); queried Redis actions, ADBHoney inputs/malware, Conpot inputs/protocols, Tanner URIs (HoneypotSpecificAgent).
    *   **Key Results**: Identified 24792 total attacks, top attacking countries and IPs, prevalent VNC and SMB scanning, detection of CVE-2025-55182 and JS Prototype Pollution, common credential brute-force attempts, and interactions with Tanner, Conpot, and Redis honeypots.
    *   **Errors or Gaps**: All sub-agents completed their queries successfully, but `KnownSignalAgent`'s `suricata_lenient_phrase_search` for 'VNC' returned 0 hits, despite high VNC activity, suggesting a potential keyword/field mismatch.

*   **CandidateDiscoveryAgent**
    *   **Purpose**: Aggregate initial findings from parallel investigations and identify potential high-signal candidates for further validation.
    *   **Inputs Used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    *   **Actions Taken**: Correlated CVEs with source IPs, queried raw events by signature/keyword, aggregated two-level terms (IP-to-port, path-to-IP, signature-to-IP).
    *   **Key Results**: Generated a comprehensive triage summary. Identified initial candidates: `ENE-2025-55182-001`, `NEC-JS-PROTO-POLLUTION-001`, `OSM-CONPOT-ICS-001`, `SUM-TANNER-ENV-001`, along with several botnet/commodity items.
    *   **Errors or Gaps**: Detected significant tool errors, including repeated `kibanna_discover_query` failures (e.g., `Expected text at 1:71 but found START_ARRAY` for `alert.signature_id`, `alert.signature.keyword`, `type.keyword:Conpot`) and `two_level_terms_aggregated` returning no buckets for `alert.signature.keyword`. This resulted in `degraded_mode: true` for the discovery process and affected the depth of initial candidate analysis.

*   **CandidateValidationLoopAgent**
    *   **Purpose**: Orchestrate the validation of discovered candidates by iterating through them.
    *   **Inputs Used**: Candidates from `CandidateDiscoveryAgent`.
    *   **Actions Taken**: Initiated a candidate queue with 4 candidates, then loaded and processed each one sequentially.
    *   **Key Results**: 4 iterations run, 4 candidates passed to `CandidateValidationAgent`.
    *   **Errors or Gaps**: None from the orchestrator itself; errors propagated from `CandidateValidationAgent`.

*   **CandidateValidationAgent**
    *   **Purpose**: Perform in-depth validation for each high-signal candidate, retrieving specific event samples and correlating infrastructure.
    *   **Inputs Used**: Individual candidate details, time window context.
    *   **Actions Taken**: For `ENE-2025-55182-001` and `NEC-JS-PROTO-POLLUTION-001`, used `suricata_cve_samples` and `suricata_signature_samples` respectively. For `OSM-CONPOT-ICS-001`, attempted `kibanna_discover_query` and `two_level_terms_aggregated`. For `SUM-TANNER-ENV-001`, attempted `kibanna_discover_query` and used `web_path_samples`.
    *   **Key Results**:
        *   `ENE-2025-55182-001`: Validated, identified source IPs, target ports/paths. Provisional: `false`.
        *   `NEC-JS-PROTO-POLLUTION-001`: Validated, identified source IPs, target ports/paths. Provisional: `false`.
        *   `OSM-CONPOT-ICS-001`: Identified protocols, but no source IPs or detailed inputs. Provisional: `true`.
        *   `SUM-TANNER-ENV-001`: Validated, identified source IPs, ASNs, and specific `.env` paths. Provisional: `false`.
    *   **Errors or Gaps**: Repeated `kibanna_discover_query` failures (e.g., `Expected text at 1:71 but found START_ARRAY` for various terms including `protocol.keyword`, `path.keyword`). `two_level_terms_aggregated` also failed for Conpot. These blocked detailed payload analysis and IP correlation for `OSM-CONPOT-ICS-001`, making it provisional.

*   **CandidateLoopReducerAgent**
    *   **Purpose**: Collect and store the results of individual candidate validations.
    *   **Inputs Used**: Output from `CandidateValidationAgent`.
    *   **Actions Taken**: Appended each validated candidate result to the workflow state.
    *   **Key Results**: Successfully added 4 validated candidates to the state, with their respective statuses (provisional or not) and identified errors/gaps.
    *   **Errors or Gaps**: None.

*   **OSINTAgent**
    *   **Purpose**: Perform external open-source intelligence lookups for key candidates to enrich knownness and context.
    *   **Inputs Used**: `cve_id` for `ENE-2025-55182-001`, signature for `NEC-JS-PROTO-POLLUTION-001`, service fingerprint for `OSM-CONPOT-ICS-001`, and path enumeration for `SUM-TANNER-ENV-001`.
    *   **Actions Taken**: Performed `search` queries for each relevant candidate.
    *   **Key Results**:
        *   `CVE-2025-55182`: Confirmed as critical RCE (React2Shell), active since Dec 2025, in CISA KEV. Confidence updated to High.
        *   `JS Prototype Pollution`: Confirmed as a known, established attack technique that can lead to RCE. Confidence updated to High.
        *   `Conpot ICS/SCADA`: Confirmed Kamstrup and Guardian AST as known ICS/SCADA attack vectors. Confidence updated to Moderate.
        *   `.env file enumeration`: Confirmed as a widespread, established reconnaissance technique. Confidence updated to High.
    *   **Errors or Gaps**: None.

*   **ReportAgent (Self)**
    *   **Purpose**: Compile the final report from all collected workflow state outputs.
    *   **Inputs Used**: All `_result` keys from the workflow state, including `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates` (from loop), `osint_validation_result`.
    *   **Actions Taken**: Consolidated, summarized, and formatted the report content according to strict output requirements.
    *   **Key Results**: Markdown report generated.
    *   **Errors or Gaps**: None in compilation, but acknowledged limitations imposed by prior agent errors.

*   **SaveReportAgent**
    *   **Purpose**: Save the generated report to a file.
    *   **Inputs Used**: The markdown report content generated by `ReportAgent`.
    *   **Actions Taken**: `default_write_file` (implied by workflow configuration).
    *   **Key Results**: File write status not explicitly provided in logs, but assumed successful if this is the end of the workflow.
    *   **Errors or Gaps**: No explicit errors recorded in the provided context for this agent. 
