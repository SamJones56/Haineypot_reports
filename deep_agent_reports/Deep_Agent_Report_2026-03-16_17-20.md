# Threat Intelligence Analysis Report

## 1) Investigation Scope
- **investigation_start:** 2026-03-16T17:00:17Z
- **investigation_end:** 2026-03-16T20:00:17Z
- **completion_status:** Partial (degraded evidence)
- **degraded_mode:** true
  - **Reason:** Multiple data retrieval and aggregation queries failed during the Candidate Discovery and Deep Investigation phases. This prevented the extraction of source IPs and other key details for several initial leads, forcing a reliance on provisional findings and workarounds.

## 2) Executive Triage Summary
- **Top Services of Interest:**
    - VNC (5901-5905/tcp): Dominated by high-volume, low-complexity commodity scanning.
    - Web (3100, 8880, 8008/tcp): Targeted by n-day exploitation attempts for CVE-2025-55182 (React2Shell).
    - ADB (5555/tcp): A malware download was observed on the Adbhoney honeypot.
    - ICS (2404/tcp): A rare interaction with the IEC104 SCADA protocol was detected.
    - SSH (22, 1039, 2350/tcp): Targeted by varied scanning activity, including reconnaissance for services on non-standard ports.
- **Top Confirmed Known Exploitation:** Activity matching `CVE-2025-55182` (React2Shell), a critical RCE vulnerability, was confirmed originating from `193.32.162.28`.
- **Top Unmapped Exploit-like Items:** A malware sample (`cf06e258e721169d18401a20085bd449c39dacea2b2da351703394f83a604d5e`) was downloaded via the Adbhoney honeypot. OSINT searches found no public information on this hash, increasing concern.
- **Botnet/Campaign Mapping Highlights:** **ASN 47890 (Unmanaged Ltd, Romania)** was identified as a significant source of varied malicious activity, including n-day exploitation and multi-protocol scanning from at least four distinct source IPs.
- **Major Uncertainties:** Due to tool failures, source IPs for the Adbhoney malware download and the IEC104 interaction could not be retrieved, preventing infrastructure mapping for these high-interest events.

## 3) Candidate Discovery Summary
Initial analysis of baseline and honeypot data identified four primary areas of interest: an Adbhoney malware download, exploitation attempts matching known CVEs, an unusual IEC104 (ICS) protocol event, and a non-standard credential brute-force pattern. However, the discovery phase was materially affected by the failure of deep-dive query tools, which prevented the validation and enrichment of most of these leads, resulting in a degraded and provisional candidate list.

## 4) Emerging n-day Exploitation

### NDE-01: CVE-2025-55182 (React2Shell) Exploitation
- **cve/signature mapping:** CVE-2025-55182 / ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)
- **evidence summary:**
    - 17 events from source IP `193.32.162.28`.
    - Payloads targeted common React/Next.js paths such as `/api/route`, `/_next/server`, and `/app`.
- **affected service/port:** 3100/tcp, 8880/tcp, 8008/tcp
- **confidence:** High
- **operational notes:** Activity is consistent with known, widespread scanning and exploitation of the React2Shell vulnerability. The source IP is part of a larger malicious ASN (47890).

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
*No candidates met the criteria for this category based on the available evidence.*

## 6) Botnet/Campaign Infrastructure Mapping

### MAP-01: Multi-purpose Attack Platform at ASN 47890
- **item_id:** MAP-01 (related to NDE-01)
- **campaign_shape:** fan-out
- **suspected_compromised_src_ips:**
    - `193.32.162.28` (CVE exploitation & broad port scanning)
    - `80.94.92.184` (Connect-only SSH scanning)
    - `80.94.92.70` (Scanning for SSH on non-standard ports)
    - `2.57.122.96` (SSH scanning)
- **ASNs / geo hints:** ASN 47890 (Unmanaged Ltd, Romania)
- **suspected_staging indicators:** None observed.
- **suspected_c2 indicators:** None observed.
- **confidence:** High
- **operational notes:** This ASN hosts multiple actors with varied TTPs, functioning as a significant source of scanning and exploitation. Activity is not limited to a single campaign. Monitoring the entire ASN for new malicious IPs is recommended.

### MAP-02 (Provisional): Unidentified Adbhoney Malware Deployment
- **item_id:** BOT-01
- **campaign_shape:** unknown
- **suspected_compromised_src_ips:** Unavailable due to query failure.
- **ASNs / geo hints:** Unavailable due to query failure.
- **suspected_staging indicators:** Malware hash `cf06e258e721169d18401a20085bd449c39dacea2b2da351703394f83a604d5e`.
- **suspected_c2 indicators:** None observed.
- **confidence:** Low
- **operational notes:** OSINT found no public record of this malware hash, increasing the priority for follow-up. The primary evidence gap is the missing source IP and download vector.

## 7) Odd-Service / Minutia Attacks

### ODD-01 (Provisional): ICS Protocol Interaction
- **service_fingerprint:** 2404/tcp (IEC 60870-5-104)
- **why it’s unusual/interesting:** Any interaction with an Industrial Control System (ICS) protocol is noteworthy due to the critical nature of the systems it typically controls.
- **evidence summary:** A single connection event was logged by the Conpot honeypot. Source IP and session details are unavailable due to query failure.
- **confidence:** Low
- **recommended monitoring pivots:** While OSINT suggests this is likely reconnaissance, any further interaction with ICS protocols should be escalated. A direct query on Conpot logs is needed to identify the source.

## 8) Known-Exploit / Commodity Exclusions
- **Commodity VNC Scanning (KEX-01):** High-volume scanning (6,852+ events) on ports 5901-5905, primarily from the US, triggering the `GPL INFO VNC server response` signature. This is background noise.
- **Generic Web Scanning (KEX-02):** Widespread, low-complexity probing for common files like `/.env`, `/config.php`, and `/boaform/admin/formLogin` on the Tanner web honeypot.
- **Common Credential Stuffing:** Brute-force attempts using standard usernames (`root`, `admin`) and passwords (`123456`, `password`).
- **Known Scanner Artifacts (BOT-02):** The username/password combination `345gs5662d34` was used in 72 attempts. OSINT confirmed this is a well-documented artifact of automated SSH/Telnet scanners and not indicative of a targeted campaign.

## 9) Infrastructure & Behavioral Classification
- **exploitation vs scanning:** The investigation identified both active exploitation (CVE-2025-55182) and widespread scanning activity.
- **campaign shape:** The activity from ASN 47890 demonstrates a fan-out shape, with multiple IPs from a single network block conducting varied attacks.
- **infra reuse indicators:** ASN 47890 is clearly reused by multiple actors for different purposes (exploitation, SSH recon on standard and non-standard ports).
- **odd-service fingerprints:** The detection of IEC104 (ICS protocol) and scanning for SSH on non-standard ports (1039, 2350) are notable behavioral fingerprints.

## 10) Evidence Appendix

### NDE-01 / MAP-01 (ASN 47890)
- **source IPs with counts:**
    - `193.32.162.28` (522 events)
    - `80.94.92.70` (58 events)
    - `80.94.92.184` (8 events)
    - `2.57.122.96` (at least 4 events)
- **ASNs / geo hints:** 47890 (Unmanaged Ltd, Romania) (788+ events)
- **target ports/services:** 22, 1039, 1159, 2023, 2350, 3008, 3100, 6001, 7443, 8003, 8008, 8880
- **paths/endpoints:** `/`, `/.env`, `/api`, `/api/route`, `/app`, `/_next`, `/_next/server`, `/boaform/admin/formLogin`
- **payload/artifact excerpts:**
    - `Signature: ET WEB_SPECIFIC_APPS React Server Components React2Shell...`
    - `Signature: ET INFO SSH session in progress on Unusual Port`
    - `Signature: ET SCAN NMAP -sS window 1024`
- **temporal checks:** Activity from this ASN was observed across the entire 3-hour investigation window.

### MAP-02 (Adbhoney Malware)
- **source IPs with counts:** unavailable
- **ASNs with counts:** unavailable
- **target ports/services:** 5555/tcp (ADB)
- **staging indicators:** `dl/cf06e258e721169d18401a20085bd449c39dacea2b2da351703394f83a604d5e.raw` (filepath), `cf06e258e721169d18401a20085bd449c39dacea2b2da351703394f83a604d5e` (SHA256 hash)
- **temporal checks:** unavailable

## 11) Indicators of Interest
- **IPs:** `193.32.162.28`, `80.94.92.184`, `80.94.92.70`, `2.57.122.96`
- **ASN:** `47890` (Unmanaged Ltd, Romania)
- **CVE:** `CVE-2025-55182`
- **File Hash (SHA256):** `cf06e258e721169d18401a20085bd449c39dacea2b2da351703394f83a604d5e`
- **HTTP Paths:** `/api/route`, `/_next/server`, `/app`
- **Signatures:** `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`, `ET INFO SSH session in progress on Unusual Port`, `ET SCAN NMAP -sS window 1024`

## 12) Backend Tool Issues
- **`kibanna_discover_query`:** This tool failed multiple times to retrieve raw logs for known events, specifically for the Adbhoney malware file and the Conpot IEC104 interaction. This directly blocked the validation of candidates `BOT-01` and `ODD-01`.
- **`top_src_ips_for_cve`:** The tool failed to return source IPs for `CVE-2025-55182` despite the initial report showing 17 hits. This required a manual, less efficient validation process.
- **`complete_custom_search`:** This aggregation tool failed repeatedly during the deep investigation of `ASN 47890`, preventing a quick assessment of top IPs and signatures. This forced a pivot to manual, sample-based analysis using different tools.
- **Weakened Conclusions:** The inability to retrieve source IPs for the malware download and ICS event means our assessment of these threats is provisional and lacks crucial infrastructure details. The aggregation failures slowed down the investigation and reduced its overall scope.

## 13) Agent Action Summary (Audit Trail)

- **agent_name:** ParallelInvestigationAgent
- **purpose:** To run initial, broad data collection queries in parallel.
- **inputs_used:** `investigation_start`, `investigation_end`.
- **actions_taken:** Executed sub-agents (Baseline, KnownSignal, CredentialNoise, HoneypotSpecific) which ran initial data gathering tools like `get_total_attacks`, `get_alert_signature`, `get_input_usernames`, and `adbhoney_malware_samples`.
- **key_results:**
    - Established baseline of 12,892 attacks.
    - Identified VNC scanning and stream anomalies as top signature noise.
    - Flagged `CVE-2025-55182`.
    - Captured Adbhoney malware hash and Conpot IEC104 protocol event.
- **errors_or_gaps:** None.

- **agent_name:** CandidateDiscoveryAgent
- **purpose:** To merge parallel results, identify interesting seeds, and generate initial candidates.
- **inputs_used:** `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken:** Merged data, identified 4 provisional seeds, attempted to enrich seeds using `kibanna_discover_query` and `top_src_ips_for_cve`, and performed OSINT on `CVE-2025-55182`.
- **key_results:**
    - Generated 4 candidates (`NDE-01`, `BOT-01`, `BOT-02`, `ODD-01`).
    - Flagged findings as provisional due to query failures.
- **errors_or_gaps:** Multiple query tools failed, preventing retrieval of source IPs and raw logs for initial candidates. The agent entered a `degraded_mode`.

- **agent_name:** CandidateValidationLoopAgent
- **purpose:** To iteratively validate candidates from the discovery phase.
- **inputs_used:** `candidate_discovery_result`.
- **actions_taken:** Loaded candidate `NDE-01`, used `suricata_cve_samples` to retrieve detailed evidence.
- **key_results:**
    - Iterations run: 1.
    - Candidates validated: 1 (`NDE-01`).
    - Successfully validated the CVE-2025-55182 activity and extracted the source IP `193.32.162.28`.
- **errors_or_gaps:** The loop was not configured to retry the failed validations from the discovery phase.

- **agent_name:** DeepInvestigationLoopController
- **purpose:** To conduct deep, iterative investigation starting from validated candidates.
- **inputs_used:** `validated_candidates`.
- **actions_taken:** Iterations run: 4. Pursued lead `src_ip:193.32.162.28`, which pivoted to `asn:47890`, then to other IPs within that ASN (`80.94.92.184`, `80.94.92.70`). Used `first_last_seen_src_ip` and `events_for_src_ip`.
- **key_results:**
    - Mapped the infrastructure of ASN 47890.
    - Identified it as a source of diverse malicious TTPs.
    - Uncovered scanning for non-standard SSH ports.
- **errors_or_gaps:** The `complete_custom_search` tool failed, forcing a slower, sample-based investigation of the ASN. The loop exited successfully after characterizing the primary infrastructure.

- **agent_name:** OSINTAgent
- **purpose:** To enrich candidates with open-source intelligence.
- **inputs_used:** `validated_candidates` (and provisional candidates from discovery).
- **actions_taken:** Performed web searches for the malware hash, the unique credential, the IEC104 protocol, and the CVE.
- **key_results:**
    - Confirmed `345gs5662d34` (BOT-02) is a known commodity scanner artifact.
    - Confirmed IEC104 (ODD-01) is a known target for reconnaissance.
    - Found no public information for the malware hash (BOT-01), increasing its significance.
    - Formalized the known-exploited status of `CVE-2025-55182` (NDE-01).
- **errors_or_gaps:** None.

- **agent_name:** ReportAgent
- **purpose:** To compile the final report from all workflow state outputs.
- **inputs_used:** All previous agent outputs.
- **actions_taken:** Assembled this report.
- **key_results:** Report generated.
- **errors_or_gaps:** None.

- **agent_name:** SaveReportAgent
- **purpose:** To save the final report artifact.
- **inputs_used:** Report content from ReportAgent.
- **actions_taken:** Will call `deep_agent_write_file`.
- **key_results:** File write status pending.
- **errors_or_gaps:** None.
