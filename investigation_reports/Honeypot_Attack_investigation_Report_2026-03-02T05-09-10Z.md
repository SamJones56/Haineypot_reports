# Honeypot Threat Hunt - Final Report

### **1) Investigation Scope**
- **investigation_start:** `2026-03-02T04:00:10Z`
- **investigation_end:** `2026-03-02T05:00:10Z`
- **completion_status:** Partial (degraded evidence)
- **degraded_mode:** true. Tool failures (`kibanna_discover_query`, `two_level_terms_aggregated`) blocked actor identification and infrastructure mapping for the VNC scanning campaign and odd-service activity.

### **2) Executive Triage Summary**
- **Top Services/Ports of Interest:** The primary activity clusters were VNC (ports 5906, 5907, 5925, 5926), widespread SSH (22) brute-forcing, and HTTP web exploitation scanning.
- **Odd-Service Activity:** Low-volume probing was observed against the IEC104 (ICS/SCADA) protocol, which is operationally significant despite the low event count.
- **Top Confirmed Known Exploitation:**
    - **CVE-2024-14007 (Shenzhen TVT NVR Info Disclosure):** Two exploit attempts were successfully attributed to a single actor: `89.42.231.179`.
    - **CVE-2017-9841 (PHPUnit RCE) & `.env` Scanning:** Activity targeting these common web vulnerabilities was identified and attributed to commodity scanners, based on OSINT validation.
- **Botnet/Campaign Mapping Highlights:** A large-scale VNC scanning campaign was identified by the `GPL INFO VNC server response` signature (1,744 events), indicating coordinated activity.
- **Major Uncertainties:** Due to tool failures, the source IP infrastructure for the large VNC scanning campaign and the actor behind the IEC104 probing could not be determined.

### **3) Candidate Discovery Summary**
- Initial analysis of 8,985 attacks identified four primary areas for investigation:
    1.  Targeted web exploitation attempts against Tanner (PHPUnit RCE, `.env` file disclosure).
    2.  Emerging n-day exploitation of `CVE-2024-14007`.
    3.  A large-scale VNC scanning campaign.
    4.  Unusual ICS/SCADA protocol activity (IEC104).
- The discovery process was materially affected by repeated failures of the `kibanna_discover_query` tool, which prevented the initial identification of actors for `CVE-2024-14007` and the VNC campaign.

### **4) Emerging n-day Exploitation**
- **CVE/Signature Mapping:** `CVE-2024-14007` - `ET WEB_SPECIFIC_APPS Shenzhen TVT NVMS-9000 Information Disclosure Attempt (CVE-2024-14007)`
- **Evidence Summary:** 2 exploit attempts were observed from a single source IP, `89.42.231.179` (ASN 206264 - AMARUTU TECHNOLOGY LTD). The actor was active for approximately 50 minutes within the window.
- **Affected Service/Port:** 9100/tcp, 17000/tcp.
- **Confidence:** High
- **Operational Notes:** The source IP belongs to a hosting provider with a mixed reputation, frequently associated with hosting abusive clients. The activity was targeted exploitation, not broad scanning.

### **5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)**
*No candidates met the criteria for this category. The primary web exploitation candidate (`NEC-001`) was re-classified as commodity scanning based on OSINT validation linking the activity to known CVEs and malicious scanner infrastructure.*

### **6) Botnet/Campaign Infrastructure Mapping**
- **item_id:** `BCM-001` (VNC Scanning Campaign)
- **campaign_shape:** spray
- **suspected_compromised_src_ips:** Unknown. (Actor identification was blocked by tool failures).
- **ASNs / geo hints:** Not available.
- **suspected_staging indicators:** None identified.
- **suspected_c2 indicators:** None identified.
- **confidence:** Medium (Provisional)
- **operational notes:** A high volume of alerts (1,744 for `GPL INFO VNC server response`) strongly indicates a coordinated campaign. However, the inability to map the source infrastructure is a critical evidence gap. This finding remains provisional pending manual queries.

### **7) Odd-Service / Minutia Attacks**
- **service_fingerprint:** protocol: `IEC104` (ICS/SCADA) on Conpot honeypot.
- **why it’s unusual/interesting:** IEC104 is an Industrial Control Systems protocol not typically seen in internet background noise. Any interaction is of potential interest.
- **evidence summary:** 2 events observed. Source actor is unknown due to query limitations.
- **confidence:** Low
- **recommended monitoring pivots:** Monitor for any increase in volume, session duration, or depth of interaction with the Conpot honeypot.

### **8) Known-Exploit / Commodity Exclusions**
- **Web Exploitation Scanning:** Activity targeting `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (CVE-2017-9841) and `/.env` files was observed from `161.248.179.37` and `78.153.140.149`. OSINT confirmed this is a common pattern from automated scanners, with IP `78.153.140.149` belonging to a network block known for this specific activity.
- **VNC Scanning Campaign:** The 1,744 events matching `GPL INFO VNC server response` across multiple VNC-related ports (59xx) are characteristic of a large-scale, non-targeted scanning campaign.
- **Credential Noise:** High volume of SSH brute-force attempts using common usernames (`root`, `admin`, `oracle`) and passwords (`123456`, `password`). This is standard internet background noise.
- **MS-TS Scanning:** Events matching `ET SCAN MS Terminal Server Traffic on Non-standard Port` are consistent with known commodity scanning behavior.

### **9) Infrastructure & Behavioral Classification**
- **exploitation vs scanning:** The investigation identified both targeted exploitation (`CVE-2024-14007`) from a single IP and large-scale, automated scanning (VNC, PHPUnit/.env).
- **campaign shape:** The VNC campaign exhibits a classic `spray` shape. The web scanning shows `fan-out` behavior from a few sources.
- **infra reuse indicators:** OSINT on `78.153.140.149` showed that the entire `/24` network block it belongs to is considered malicious, indicating infrastructure reuse by a single malicious operator. The actor `89.42.231.179` originates from an ASN (`206264`) known for hosting abusive clients.
- **odd-service fingerprints:** Probing of the `IEC104` (ICS/SCADA) protocol was a notable outlier.

### **10) Evidence Appendix**
**Item: Emerging n-day Exploitation (CVE-2024-14007)**
- **source IPs:** `89.42.231.179` (count: 2)
- **ASNs:** `206264` - AMARUTU TECHNOLOGY LTD (count: 2)
- **target ports/services:** 9100, 17000
- **payload/artifact excerpts:** N/A (Alert based on `ET WEB_SPECIFIC_APPS Shenzhen TVT NVMS-9000 Information Disclosure Attempt (CVE-2024-14007)` signature)
- **temporal checks results:** Actor first seen at `2026-03-02T04:09:57.000Z` and last seen at `2026-03-02T05:00:10.000Z`.

**Item: Botnet Mapping (BCM-001 - VNC Campaign)**
- **source IPs:** `Unknown`
- **ASNs:** `Unknown`
- **target ports/services:** 5906, 5907, 5925, 5926, and others.
- **payload/artifact excerpts:** `GPL INFO VNC server response` signature (count: 1,744)

**Item: Known Web Exploitation (Formerly NEC-001)**
- **source IPs:** `161.248.179.37` (count: 2), `78.153.140.149` (count: 1)
- **target ports/services:** HTTP (Tanner Honeypot)
- **paths/endpoints:** `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (count: 1), `/.env` (count: 2)

### **11) Indicators of Interest**
- **IPs:**
    - `89.42.231.179` (Targeted `CVE-2024-14007` exploitation)
    - `78.153.140.149` (Commodity `.env` scanning from a known malicious block)
    - `161.248.179.37` (Commodity `CVE-2017-9841` and `.env` scanning)
- **ASNs:**
    - `206264` (AMARUTU TECHNOLOGY LTD / KoDDoS - Provider for CVE-2024-14007 actor)
- **Paths/URIs:**
    - `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    - `/.env`
- **Signatures:**
    - `ET WEB_SPECIFIC_APPS Shenzhen TVT NVMS-9000 Information Disclosure Attempt (CVE-2024-14007)`

### **12) Backend Tool Issues**
- **`kibanna_discover_query`:** This tool failed multiple times with a `400 Bad Request` error. This directly blocked the identification of source IPs for `CVE-2024-14007` during discovery and prevented further investigation into ASN `206264` during the deep dive.
- **`two_level_terms_aggregated`:** This tool failed to return results when aggregating on the `alert.signature.keyword` field. This prevented the mapping of source IPs for the large-scale VNC scanning campaign.
- **Weakened Conclusions:** The inability to identify source actors for the VNC campaign (`BCM-001`) and the IEC104 activity means these findings remain provisional and lack actionable infrastructure details.

### **13) Agent Action Summary (Audit Trail)**
- **agent_name:** ParallelInvestigationAgent
- **purpose:** Gather initial telemetry across baseline, known signal, credential, and honeypot-specific domains.
- **inputs_used:** `investigation_start`, `investigation_end`.
- **actions_taken:** Executed sub-agents to query for total attacks, top talkers, alert signatures, credentials, and honeypot-specific artifacts.
- **key_results:** Baseline of 8,985 attacks; identified high-volume VNC scanning, `CVE-2024-14007` alerts, PHPUnit/.env web probes, and IEC104 ICS activity.
- **errors_or_gaps:** None.

- **agent_name:** CandidateDiscoveryAgent
- **purpose:** Analyze initial telemetry to identify high-signal leads for investigation.
- **inputs_used:** `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken:** Executed multiple pivot queries (`two_level_terms_aggregated`, `kibanna_discover_query`, `search`) to correlate activity.
- **key_results:** Generated 4 primary candidates for validation. Successfully identified source IPs for the web exploitation activity (`NEC-001`).
- **errors_or_gaps:** Multiple `kibanna_discover_query` and `two_level_terms_aggregated` failures blocked actor identification for the CVE and VNC campaigns, resulting in a degraded output.

- **agent_name:** CandidateValidationLoopAgent
- **purpose:** Systematically validate candidates generated during discovery.
- **inputs_used:** `candidate_discovery_result`.
- **actions_taken:** Iterations run: 1. Validated one candidate (`CVE-2024-14007`) using `suricata_signature_samples` to find raw events and `events_for_src_ip` to confirm the actor's activity.
- **key_results:** Successfully identified `89.42.231.179` as the source of `CVE-2024-14007` exploitation, resolving a key evidence gap from discovery.
- **errors_or_gaps:** The loop exited after validating only one of the four candidates, leaving the others in a provisional state.

- **agent_name:** DeepInvestigationLoopController
- **purpose:** Conduct a detailed, pivot-based investigation on the top validated candidate.
- **inputs_used:** `validated_candidates`.
- **actions_taken:** Iterations run: 4. Pursued lead `src_ip:89.42.231.179`. Used `first_last_seen_src_ip` to establish a timeline and `search` to gather OSINT on the IP and its ASN.
- **key_results:** Confirmed the actor's activity window and targets (ports 9100, 17000). OSINT confirmed the actor's ASN (`206264`) is associated with hosting malicious activity.
- **errors_or_gaps:** The investigation stalled and exited after a `kibanna_discover_query` call failed, blocking attempts to pivot from the ASN to related infrastructure.

- **agent_name:** OSINTAgent
- **purpose:** Enrich candidates with external intelligence to validate novelty and map to known threats.
- **inputs_used:** `candidate_discovery_result` (`NEC-001`).
- **actions_taken:** Executed 4 `search` queries on exploit paths and source IPs for the web exploitation candidate.
- **key_results:** Successfully mapped the PHPUnit path to `CVE-2017-9841` and `.env` access to a common scanning technique. Found strong negative reputation for actor `78.153.140.149` and its network, effectively re-classifying the candidate from "novel" to "commodity".
- **errors_or_gaps:** None.

- **agent_name:** ReportAgent
- **purpose:** Builds finale report from workflow state (no new searching).
- **inputs_used:** All available workflow state outputs.
- **actions_taken:** Consolidated evidence, resolved conflicting findings (e.g., re-classifying `NEC-001`), determined final completion status, and formatted the report.
- **key_results:** This report.
- **errors_or_gaps:** None.

- **agent_name:** SaveReportAgent
- **purpose:** Persists the final report file to storage.
- **inputs_used:** Final report content.
- **actions_taken:** Pending downstream tool call to `investigation_write_file`.
- **key_results:** Not yet available.
- **errors_or_gaps:** Not yet available.