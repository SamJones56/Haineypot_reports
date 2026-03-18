# 1) Investigation Scope

- investigation_start: 2026-03-08T06:00:04Z
- investigation_end: 2026-03-08T09:00:04Z
- completion_status: Complete
- degraded_mode: false

2) Executive Triage Summary

- Total attacks observed: 17,623
- Top services of interest: VNC (ports 5902, 5903, 5904), SMB (port 445), SSH (port 22), ADBHoney, Redishoneypot, Tanner.
- Top confirmed known exploitation: Widespread VNC server response scanning, MS Terminal Server traffic on non-standard ports.
- Top unmapped exploit-like items: None. Initial "novel" binary probe was reclassified as known scanning.
- Botnet/campaign mapping highlights: Android TV botnet activity detected, attempting malware installation and reconnaissance.
- Critical Reclassification: A binary payload initially flagged as a novel exploit candidate was identified via OSINT and deep investigation as a known TLS handshake failure probe used by security scanning services, specifically VisionHeight.com. This significantly reduces its novelty and threat level.

3) Candidate Discovery Summary

- Total honeypot interactions: 17,623
- Top attacking countries: United States (5049), Indonesia (1534), Türkiye (1080).
- Top source ASNs: DigitalOcean, LLC (AS14061, 4105), Google LLC (AS396982, 1433), Emre Anil Arslan (AS216099, 945).
- Key activity identified: VNC scanning, SMB scanning, SSH scanning, ADBHoney botnet commands, unusual Redis commands, GeoServer probes, and a specific binary TLS probe.
- No material missing inputs or errors affected the overall discovery process.

4) Emerging n-day Exploitation

No exploitation events were classified as "Emerging n-day Exploitation" after validation. All CVE-mapped activity was deemed commodity scanning or exploitation of older, widely-known vulnerabilities.

5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)

No items remain classified as "Novel or Zero-Day Exploit Candidates" after investigation and validation.

6) Botnet/Campaign Infrastructure Mapping

- **item_id**: BOTNET-ANDROID-TV-01
    - **campaign_shape**: fan-in
    - **suspected_compromised_src_ips**: 110.18.137.191 (attempts to install `tv.apk`), 223.104.83.218 (checks for `com.ufo.miner`, removes `ufo.apk`)
    - **ASNs / geo hints**: Unknown for these specific IPs.
    - **suspected_staging indicators**: None identified explicitly, but malware filenames `tv.apk` and `ufo.apk` suggest staging.
    - **suspected_c2 indicators**: None explicitly identified from the provided logs.
    - **confidence**: High
    - **operational notes**: This campaign targets Android TV devices, attempting to install unknown malware. The activity from 223.104.83.218 suggests potential conflict or competition with other malware on compromised devices. Monitor these IPs and malware filenames.

7) Odd-Service / Minutia Attacks

- **item_id**: ODD-REDIS-COMMANDS-01
    - **service_fingerprint**: Port 6379 / Redis
    - **why it’s unusual/interesting**: The Redishoneypot received binary data (`\x15\x03\x01\x00\x02\x02\x16` and similar) that are not valid Redis commands. This suggests a non-Redis protocol probe or an attempted exploit targeting a different service mistakenly connecting to Redis. This specific payload was later identified as a TLS handshake failure probe (see Known-Exploit / Commodity Exclusions).
    - **evidence summary**: 4 total events of binary data being sent to Redis honeypots, from source IPs including 3.151.241.153 (US, Amazon) and 77.90.185.17 (Iran, Limited Network LTD).
    - **confidence**: High
    - **recommended monitoring pivots**: Monitor for this specific binary string on other ports/protocols.

8) Known-Exploit / Commodity Exclusions

-   **VNC Scanning Activity**: High volume (28,877 events) of 'GPL INFO VNC server response' signatures, indicating widespread VNC scanning on ports 5902, 5903, 5904, predominantly from the United States.
-   **GeoServer Vulnerability Scanning**: A single request for '/geoserver/web/' from IP 65.49.1.122. OSINT confirmed numerous known CVEs for GeoServer, indicating scanning for public vulnerabilities.
-   **Credential Stuffing**: Frequent attempts with common usernames ('root', 'admin') and passwords ('123456', 'password'). A notable credential pair '345gs5662d34' was used 55 times, suggesting automated brute-forcing activity.
-   **MS Terminal Server Scanning**: 643 events for 'ET SCAN MS Terminal Server Traffic on Non-standard Port'.
-   **TLS Handshake Failure Probe (Reclassified from Novel Candidate)**:
    -   **candidate_id**: NOVEL-EXPLOIT-01
    -   **seed_reason**: Unusual binary data `\x15\x03\x01\x00\x02\x02\x16` observed across multiple honeypots (Redis, Cowrie) on ports 6379 and 443.
    -   **observed_evidence**: The binary payload was sent by source IPs 3.151.241.153 (Amazon, US) and 77.90.185.17 (Limited Network LTD, Iran). Deep investigation and OSINT confirm this payload corresponds to a TLS 1.0 fatal alert (handshake_failure, unsupported_extension).
    -   **Knownness checks performed**: Keyword search, OSINT for TLS alerts, pivot on user agent.
    -   **Confidence**: High (now known as scanner activity).
    -   **Operational notes**: This is identified as a common fingerprinting technique, particularly used by security scanners like VisionHeight.com (associated with 3.151.241.153). While anomalous when sent to non-TLS services (like Redis), it is a known scanning pattern, not a novel exploit. The observation from a distinct IP (77.90.185.17) suggests it's a widely adopted scanning TTP.

9) Infrastructure & Behavioral Classification

-   **Exploitation vs. Scanning**: The majority of observed activity is scanning (VNC, SMB, SSH, GeoServer, TLS probes). Direct exploitation evidence is limited to the ADBHoney botnet commands for malware installation.
-   **Campaign Shape**:
    -   ADBHoney activity shows a "fan-in" pattern, where multiple attackers interact with the honeypot for Android TV malware.
    -   VNC, SMB, SSH, and TLS probes appear to be wide-area "spray" scanning, typical of internet-wide reconnaissance.
-   **Infra Reuse Indicators**: The TLS handshake failure probe (formerly NOVEL-EXPLOIT-01) being used by two distinct source IPs (one identified as a legitimate scanner, the other unknown but from Iran) suggests a shared or publicly available scanning tool/TTP.
-   **Odd-Service Fingerprints**: Significant activity on Redis (6379) with non-Redis, binary TLS data, indicating misdirected or specialized scanning attempts.

10) Evidence Appendix

-   **BOTNET-ANDROID-TV-01**
    -   **Source IPs with counts**: 110.18.137.191 (multiple actions), 223.104.83.218 (multiple actions)
    -   **ASNs with counts**: Unknown
    -   **Target ports/services**: ADB (usually 5555, inferred from ADBHoney)
    -   **Paths/endpoints**: `/data/local/tmp/tv.apk`, `/data/local/tmp/*`
    -   **Payload/artifact excerpts**: `pm path com.ufo.miner`, `rm -rf /data/local/tmp/*`, `am start -n com.google.home.tv/com.example.test.MainActivity`, `pm install /data/local/tmp/tv.apk`
    -   **Staging indicators**: `tv.apk`, `ufo.apk`
    -   **Temporal checks results**: Unavailable

-   **TLS Handshake Failure Probe (Reclassified from Novel Candidate NOVEL-EXPLOIT-01)**
    -   **Source IPs with counts**: 3.151.241.153 (2 events to Redis), 77.90.185.17 (2 events to Cowrie)
    -   **ASNs with counts**: AS16509 (Amazon.com, Inc. - for 3.151.241.153), AS213790 (Limited Network LTD - for 77.90.185.17)
    -   **Target ports/services**: 6379 (Redis), 443 (Cowrie, simulating TLS)
    -   **Paths/endpoints**: N/A (direct TCP/TLS probes)
    -   **Payload/artifact excerpts**: `\x15\x03\x01\x00\x02\x02\x16` (TLS 1.0 Fatal Alert: Handshake Failure)
    -   **Staging indicators**: None
    -   **Temporal checks results**: `3.151.241.153` active from 2026-03-08T06:00:53Z to 2026-03-08T08:47:38Z; `77.90.185.17` active from 2026-03-08T06:38:12Z to 2026-03-08T07:41:51Z.

-   **GEOSERVER-PROBE-01**
    -   **Source IPs with counts**: 65.49.1.122 (1 event)
    -   **ASNs with counts**: Unknown
    -   **Target ports/services**: HTTP/S (implied by path, Tanner honeypot)
    -   **Paths/endpoints**: `/geoserver/web/`
    -   **Payload/artifact excerpts**: GET request for `/geoserver/web/`
    -   **Staging indicators**: None
    -   **Temporal checks results**: Unavailable

-   **VNC-SCAN-01**
    -   **Source IPs with counts**: Not explicitly broken down by IP in aggregate, but observed across many IPs.
    -   **ASNs with counts**: Primarily DigitalOcean (AS14061), Google (AS396982), others.
    -   **Target ports/services**: 5902, 5903, 5904 (VNC)
    -   **Paths/endpoints**: N/A
    -   **Payload/artifact excerpts**: "GPL INFO VNC server response" signature.
    -   **Staging indicators**: None
    -   **Temporal checks results**: Unavailable

11) Indicators of Interest

-   **Source IPs**:
    -   110.18.137.191 (Suspected Android TV botnet C2/staging)
    -   223.104.83.218 (Suspected Android TV botnet C2/staging)
    -   77.90.185.17 (Iranian IP using TLS probe and SSH scanning)
    -   3.151.241.153 (US Amazon IP, VisionHeight scanner using TLS probe)
    -   65.49.1.122 (GeoServer probe)
-   **User Agents**:
    -   `visionheight.com/scan Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36`
-   **Payload Fragments**:
    -   `\x15\x03\x01\x00\x02\x02\x16` (TLS handshake failure probe)
-   **Honeypot Commands**:
    -   `pm install /data/local/tmp/tv.apk`
    -   `pm path com.ufo.miner`
    -   `rm -rf /data/local/tmp/*`
-   **Credentials**:
    -   Username: `345gs5662d34`, Password: `345gs5662d34`

12) Backend Tool Issues

-   **CandidateDiscoveryAgent**: `kibanna_discover_query` tool returned no results when searching for the exact binary string payload `\x15\x03\x01\x00\x02\x02\x16`. This required a pivot to `two_level_terms_aggregated` to successfully identify the activity. This issue did not prevent discovery but highlighted string handling limitations.
-   **DeepInvestigationAgent**: When investigating the user agent `visionheight.com/scan Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36`, both `two_level_terms_aggregated` and `kibanna_discover_query` failed to return results using the exact string. This indicates potential indexing or exact match limitations for complex user agent strings and required a pivot to a keyword search for `visionheight.com`.

13) Agent Action Summary (Audit Trail)

-   **ParallelInvestigationAgent (and its sub-agents)**
    -   **purpose**: Gather baseline, known signal, credential noise, and honeypot-specific telemetry.
    -   **inputs_used**: time_window
    -   **actions_taken**:
        -   BaselineAgent: queried total attacks, top countries, attacker IPs, country-to-port, attacker ASNs.
        -   KnownSignalAgent: queried alert signatures, CVEs, alert categories, lenient phrase search for "ET".
        -   CredentialNoiseAgent: queried input usernames, input passwords, p0f OS distribution.
        -   HoneypotSpecificAgent: queried Redis actions, ADBHoney inputs, ADBHoney malware samples, Tanner uniform resource paths, Conpot inputs/protocols.
    -   **key_results**:
        -   17,623 total attacks.
        -   Top attacks from US, Indonesia, Türkiye.
        -   DigitalOcean and Google were top ASNs.
        -   Heavy VNC scanning (GPL INFO VNC server response: 28877 events).
        -   CVE-2025-55182 (90 events).
        -   Common credential stuffing detected.
        -   ADBHoney showed malware installation attempts.
        -   Redishoneypot observed unusual binary commands.
        -   Tanner recorded probes for common web paths (e.g., `/`, `/.env`, `/geoserver/web/`).
    -   **errors_or_gaps**: None.

-   **CandidateDiscoveryAgent**
    -   **purpose**: Identify potential high-signal attack candidates and map initial known activity.
    -   **inputs_used**: All results from ParallelInvestigationAgent.
    -   **actions_taken**:
        -   Aggregated ADBHoney inputs by src_ip.
        -   Queried Redishoneypot events.
        -   Searched for keyword `\x15\x03\x01\x00\x02\x02\x16` (binary payload).
        -   Performed OSINT search for "cve for GeoServer".
        -   Aggregated Tanner paths by src_ip.
    -   **key_results**:
        -   Identified ADBHoney botnet activity (`BOTNET-ANDROID-TV-01`).
        -   Flagged unusual binary payload in Redis/Cowrie as `NOVEL-EXPLOIT-01`.
        -   Identified GeoServer probe activity (`GEOSERVER-PROBE-01`).
        -   Mapped high-volume VNC scanning as `VNC-SCAN-01`.
        -   Summarized credential noise and odd Redis commands.
    -   **errors_or_gaps**: `kibanna_discover_query` failed for the binary string, but subsequent actions mitigated this.

-   **CandidateValidationLoopAgent**
    -   **iterations run**: 1
    -   **# candidates validated**: 1 (`NOVEL-EXPLOIT-01`)
    -   **any early exit reason**: The single novel candidate was validated, leading to the loop exit.
    -   **purpose**: Validate discovered candidates using further queries and OSINT.
    -   **inputs_used**: `NOVEL-EXPLOIT-01` candidate details.
    -   **actions_taken**:
        -   Searched `kibanna_discover_query` for `\x15\x03\x01\x00\x02\x02\x16` (payload).
        -   Aggregated Redishoneypot actions by src_ip.
        -   Performed OSINT search for `TLS alert vulnerability scanner \x15\x03\x01\x00\x02\x02\x16`.
    -   **key_results**:
        -   Confirmed source IPs for the binary payload (3.151.241.153, 77.90.185.17).
        -   OSINT identified the binary string as a known TLS 1.0 handshake failure alert.
        -   The candidate was reclassified from "novel exploit" to "botnet_campaign_mapping" (later refined by OSINT to known scanner).
    -   **errors_or_gaps**: `kibanna_discover_query` failed to find the payload when directly querying the `action` field, leading to reliance on `two_level_terms_aggregated` for IP context.

-   **DeepInvestigationLoopController**
    -   **iterations run**: 3
    -   **key leads pursued**: `src_ip:3.151.241.153`, `ua:visionheight.com/scan Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36`, `src_ip:77.90.185.17`.
    -   **stall/exit reason**: All primary leads from the `NOVEL-EXPLOIT-01` reclassification were investigated and resolved, no new high-priority leads were generated for further deep investigation.
    -   **purpose**: Investigate high-signal leads identified during candidate validation.
    -   **inputs_used**: Validated candidate `NOVEL-EXPLOIT-01` details, including associated IPs and user agents.
    -   **actions_taken**:
        -   Gathered all events and first/last seen for `src_ip:3.151.241.153`.
        -   Attempted to pivot on `http.user_agent.keyword` for `visionheight.com/scan...` (failed), then successfully keyword searched `visionheight.com`.
        -   Performed OSINT search for `visionheight.com scan`.
        -   Gathered all events and first/last seen for `src_ip:77.90.185.17`.
    -   **key_results**:
        -   `src_ip:3.151.241.153` identified as an Amazon AWS IP, conducting broad scanning activities including SSH, HTTP, and Redis/TLS probes.
        -   The user agent `visionheight.com/scan` was confirmed via OSINT to belong to a legitimate cybersecurity scanning service, VisionHeight.com. This reclassified the threat from `3.151.241.153` as known security scanning.
        -   `src_ip:77.90.185.17` (Iran) was found to be a general scanner for SSH and also using the binary TLS probe, indicating this specific probe is a shared TTP.
    -   **errors_or_gaps**: Exact user agent string searches failed, requiring a less precise keyword search.

-   **OSINTAgent**
    -   **purpose**: Perform open-source intelligence lookups for candidates.
    -   **inputs_used**: `NOVEL-EXPLOIT-01` candidate details, specific search terms for TLS alert and VisionHeight.
    -   **actions_taken**:
        -   OSINT search for `TLS alert vulnerability scanner \x15\x03\x01\x00\x02\x02\x16`.
        -   OSINT search for `visionheight.com scan`.
    -   **key_results**:
        -   The binary payload was identified as a TLS 1.0 fatal alert (handshake_failure).
        -   `visionheight.com` was identified as a legitimate cybersecurity company performing active scanning.
        -   This information significantly reduced the novelty score of `NOVEL-EXPLOIT-01`, reclassifying it from a novel threat to a known scanning technique.
    -   **errors_or_gaps**: None.

-   **ReportAgent (self)**
    -   **purpose**: Compile the final report from workflow state outputs.
    -   **inputs_used**: All aggregated state outputs from previous agents.
    -   **actions_taken**: Compilation of this report.
    -   **key_results**: A structured security report summarizing the investigation.
    -   **errors_or_gaps**: None.

-   **SaveReportAgent**
    -   **purpose**: Save the compiled report.
    -   **inputs_used**: The markdown report content generated by ReportAgent.
    -   **actions_taken**: N/A (this is a placeholder for a tool call that would save the report, no explicit tool call shown in the provided context for this agent).
    -   **key_results**: N/A (would be file path/identifier if executed).
    -   **errors_or_gaps**: None.
