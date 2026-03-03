# Investigation Report: Threat Hunt 2026-03-02

## 1) Investigation Scope
- **investigation_start:** 2026-03-02T09:00:12Z
- **investigation_end:** 2026-03-02T10:00:12Z
- **completion_status:** Partial (degraded evidence)
- **degraded_mode:** true. The investigation was hindered by multiple backend tool failures. These errors blocked key validation steps, including the retrieval of source IPs for a Redis RCE campaign and direct inspection of event logs for a confirmed botnet actor.

## 2) Executive Triage Summary
- **Top Services/Ports of Interest:** Activity was centered on Android Debug Bridge (ADB) on port 5555, Redis services (port unconfirmed), and unusual VNC scanning on non-standard ports TCP/5925 and TCP/5926.
- **Top Confirmed Known Exploitation:**
    - A complete, multi-step execution chain of the **Trinity (com.ufo.miner) Android botnet malware** was observed via ADB, originating from a single source IP (`14.152.90.227`).
    - A known **Redis Remote Code Execution (RCE)** technique using `SLAVEOF` and `MODULE LOAD` commands was identified, pointing to a malicious staging host (`8.218.234.50`). OSINT links this TTP to cryptomining malware like HeadCrab and P2PInfect.
- **Top Unmapped Exploit-like Items:** No novel exploit candidates were validated in this window.
- **Botnet/Campaign Mapping Highlights:**
    - Mapped a compromised source IP (`14.152.90.227`) belonging to the Trinity ADB botnet.
    - Identified a suspected malicious Redis master/staging host (`8.218.234.50`) used in a commodity RCE campaign.
- **Major Uncertainties:**
    - The source IPs participating in the Redis RCE campaign could not be identified due to tool failures, preventing a full mapping of that campaign's infrastructure.
    - Activity related to `CVE-2025-55182` was observed, but source IPs could not be retrieved, making attribution impossible.

## 3) Candidate Discovery Summary
Initial triage identified four primary areas of interest from over 10,000 attacks:
- **Adbhoney Execution Chain:** A clear sequence of `trinity` malware commands.
- **Redis RCE Technique:** Use of the `SLAVEOF` command pointing to a staging host.
- **Emerging N-day Activity:** 24 events linked to `CVE-2025-55182`.
- **Odd-Service Behavior:** High-volume VNC-related alerts correlated with non-standard ports 5925 and 5926.

Discovery was materially affected by failures in `kibanna_discover_query` and `two_level_terms_aggregated` tools, which prevented the correlation of source IPs to the Redis and VNC activity, requiring provisional assessments.

## 4) Emerging n-day Exploitation
- **Mapping:** CVE-2025-55182
- **Evidence Summary:**
    - **Counts:** 24 events.
    - **Artifacts:** No specific payloads or paths were identified. Activity consisted of connections to multiple ports.
- **Affected Service/Port:** HTTP / Web Proxy (Ports 80, 81, 3000, 3001, 3002, 3003, 3004, 3005, 3006, 3009).
- **Confidence:** Medium
- **Operational Notes:** This activity is marked as **Provisional** due to the inability to retrieve associated source IPs. The wide, sequential port scanning suggests a reconnaissance or fan-out exploitation attempt. The future-dated CVE may indicate a signature quality issue or a pre-emptive classification.

## 6) Botnet/Campaign Infrastructure Mapping
### BCM-1: Trinity Android Botnet (ADB Exploitation)
- **item_id:** BCM-1
- **campaign_shape:** Single-source attack
- **suspected_compromised_src_ips:** `14.152.90.227`
- **ASNs / geo hints:** ASN 134763 (CHINANET Guangdong province network), China.
- **suspected_staging indicators:** None. Malware was pushed directly from the source IP.
- **suspected_c2 indicators:** None identified.
- **confidence:** High
- **operational notes:** The source IP `14.152.90.227` should be blocked. The observed TTPs—including downloading `ufo.apk` and executing `/data/local/tmp/trinity`—are confirmed indicators of the commodity Trinity cryptomining botnet.

### BCM-2: Redis RCE Campaign (SLAVEOF Exploit)
- **item_id:** BCM-2
- **campaign_shape:** Fan-in (from unknown sources to a central staging host).
- **suspected_compromised_src_ips:** **Unavailable due to tool failure.**
- **ASNs / geo hints:** Unavailable.
- **suspected_staging indicators:**
    - **IP/Port:** `8.218.234.50:60130`
    - **Evidence:** This IP was used as the master in a `SLAVEOF` command, a known technique for a rogue server to send a malicious module (`exp.so`) for RCE.
- **suspected_c2 indicators:** None identified beyond the staging host.
- **confidence:** High (based on TTP)
- **operational notes:** Connections to the staging host `8.218.234.50` on port `60130` should be blocked. OSINT confirms this is a well-known commodity attack pattern used by cryptojacking malware like HeadCrab and P2PInfect.

## 7) Odd-Service / Minutia Attacks
- **service_fingerprint:** VNC on TCP/5925 and TCP/5926.
- **why it’s unusual/interesting:** These are non-standard ports for VNC, indicating targeted scanning against potentially misconfigured services.
- **evidence summary:**
    - **Counts:** 2,009 events with the signature "GPL INFO VNC server response."
    - **Correlation:** Baseline data shows 511 events on ports 5925 and 5926, which strongly suggests these are the target ports for the VNC scanning campaign. A programmatic link could not be established due to tool errors.
- **confidence:** Medium
- **recommended monitoring pivots:** Monitor these ports for any behavior beyond initial scanning, such as authentication attempts or data transfer.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise:** Standard brute-force activity was observed using common usernames (`postgres`, `root`, `admin`) and passwords (`123456`, `password`). This is low-value background noise.
- **Known Bot Patterns / Exploits:**
    - **Trinity (ADB/5555):** Activity from `14.152.90.227` is part of a known Android cryptomining botnet.
    - **Redis RCE (SLAVEOF):** The use of a malicious master (`8.218.234.50`) to load `exp.so` is a known commodity exploit.
- **Scanning Activity:**
    - High-volume scanning for VNC on non-standard ports (5925, 5926).
    - Widespread scanning for SSH (port 22) and MS Terminal Server (non-standard ports).
    - Low-grade web scanning for common paths like `/.env` and `/user/login`.

## 9) Infrastructure & Behavioral Classification
- **Trinity Campaign (BCM-1):** Classified as **Exploitation**. The campaign shape was a single-source attack targeting ADB on port 5555.
- **Redis RCE Campaign (BCM-2):** Classified as **Exploitation**. The campaign shape was a fan-in, with unknown sources using a central staging host (`8.218.234.50`) for the attack.
- **CVE-2025-55182 Activity:** Classified as **Scanning**. The campaign shape was a fan-out across a range of HTTP/proxy ports.
- **VNC Activity (OSM-1):** Classified as **Scanning**. The campaign shape was a broad spray across the internet targeting non-standard VNC ports.

## 10) Evidence Appendix
### BCM-1: Trinity Android Botnet
- **source IPs:** `14.152.90.227` (65 events from this IP)
- **ASNs:** 134763 (CHINANET Guangdong province network, China)
- **target ports/services:** 5555/TCP (ADB)
- **payload/artifact excerpts:** `/data/local/tmp/nohup /data/local/tmp/trinity`, `pm install /data/local/tmp/ufo.apk`
- **temporal checks:** Activity observed in a short burst between `2026-03-02T09:11:29.000Z` and `2026-03-02T09:24:49.699Z`.

### BCM-2: Redis RCE Campaign
- **source IPs:** Unavailable
- **ASNs:** Unavailable
- **target ports/services:** Redis
- **payload/artifact excerpts:** `SLAVEOF 8.218.234.50 60130`, `MODULE LOAD /tmp/exp.so`
- **staging indicators:** `8.218.234.50:60130`
- **temporal checks:** Unavailable

### Emerging n-day: CVE-2025-55182
- **source IPs:** Unavailable
- **ASNs:** Unavailable
- **target ports/services:** 80, 81, 3000-3006, 3009 (HTTP/Proxy)
- **staging indicators:** None
- **temporal checks:** Unavailable

## 11) Indicators of Interest
- **IPs:**
    - `14.152.90.227` (Compromised source host, Trinity botnet)
    - `8.218.234.50` (Malicious Redis staging host)
- **Artifacts/Payloads:**
    - `trinity` (ADB malware executable)
    - `ufo.apk` (Android package associated with Trinity)
    - `exp.so` (Malicious Redis module for RCE)
- **CVEs:**
    - `CVE-2025-55182` (Associated with broad web/proxy port scanning)

## 12) Backend Tool Issues
- **`kibanna_discover_query` / `match_query`:** These tools failed repeatedly with an `illegal_argument_exception` when querying IP address fields. This blocked the direct inspection of raw logs for the Trinity botnet actor, forcing reliance on aggregated data.
- **`two_level_terms_aggregated`:** This tool failed on specific field combinations. This was the primary reason the source IPs for the Redis RCE campaign (BCM-2) and the definitive port mapping for the VNC scanning (OSM-1) could not be determined. These failures significantly weakened the conclusions for those items.

## 13) Agent Action Summary (Audit Trail)
- **agent_name:** ParallelInvestigationAgent
- **purpose:** Gathers initial telemetry across different data sources.
- **inputs_used:** `investigation_start`, `investigation_end`.
- **actions_taken:** Executed baseline, known signal, credential noise, and honeypot-specific data queries in parallel.
- **key_results:** Provided foundational data on top IPs/ASNs, alert signatures, CVEs, common credentials, and honeypot-specific commands (Redis, Adbhoney).
- **errors_or_gaps:** None.

- **agent_name:** CandidateDiscoveryAgent
- **purpose:** Triage parallel outputs to generate initial investigation candidates.
- **inputs_used:** `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken:** Merged parallel results, identified 4 seeds (Adbhoney, Redis, CVE, VNC), ran OSINT searches, and attempted to correlate data using aggregation queries.
- **key_results:** Successfully identified and created four initial candidates for validation (BCM-1, BCM-2, CVE-2025-55182, OSM-1) with supporting evidence.
- **errors_or_gaps:** Multiple query tools (`kibanna_discover_query`, `two_level_terms_aggregated`) failed, preventing retrieval of source IPs for the Redis campaign and forcing a provisional status on several findings.

- **agent_name:** CandidateValidationLoopAgent
- **purpose:** Perform initial, structured validation of discovered candidates.
- **inputs_used:** Candidate queue from CandidateDiscoveryAgent.
- **actions_taken:** Loaded and attempted to validate candidate BCM-1.
- **key_results:** Processed one candidate (BCM-1) and prepared it for deep investigation.
- **errors_or_gaps:** The validation of BCM-1 was incomplete due to `kibanna_discover_query` and `match_query` failures, which blocked direct log inspection and ASN/Geo lookup. It only processed one of the four queued candidates before handing off.

- **agent_name:** DeepInvestigationLoopController
- **purpose:** Conduct an in-depth, iterative investigation on high-value, validated candidates.
- **inputs_used:** Validated candidate BCM-1.
- **actions_taken:** Ran 3 iterations, pivoting on leads: `src_ip:14.152.90.227`, `asn:134763`, and `service:5555/tcp/adb`. Used specialized IP tools (`first_last_seen_src_ip`, `events_for_src_ip`) to bypass earlier tool failures.
- **key_results:** Confirmed attack timeline, ASN, and Geo details for `14.152.90.227`. Verified it was the sole IP involved in the Trinity campaign in this window.
- **errors_or_gaps:** The investigation stalled after exhausting all leads related to the single source IP. Pivots from the ASN failed due to tool errors.

- **agent_name:** OSINTAgent
- **purpose:** Enrich candidates with public threat intelligence.
- **inputs_used:** Candidate BCM-2.
- **actions_taken:** Performed searches on "Redis SLAVEOF exploit", the staging IP `8.218.234.50`, and the artifact "exp.so".
- **key_results:** Confirmed the Redis RCE technique is a known TTP for cryptomining malware (HeadCrab, P2PInfect). Found no public threat intelligence on the specific staging IP.
- **errors_or_gaps:** None.

- **agent_name:** ReportAgent
- **purpose:** Compile the final report from all available workflow state.
- **inputs_used:** All previous agent outputs and state keys.
- **actions_taken:** Assembled this report.
- **key_results:** This document.
- **errors_or_gaps:** None.
