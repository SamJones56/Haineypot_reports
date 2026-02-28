# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start:** 2026-02-28T06:30:11Z
- **investigation_end:** 2026-02-28T07:00:11Z
- **completion_status:** Partial (degraded evidence)
  - The initial Candidate Discovery phase was significantly hindered by backend tool failures, preventing aggregation and correlation of suspicious indicators. This required the Validation phase to use alternative methods to investigate leads, and it is possible other correlations were missed.

### 2. Candidate Discovery Summary
- In the 30-minute window, 1,753 attacks were observed, dominated by commodity scanning against VNC and SSH services.
- Initial analysis flagged two items for investigation: an Android Debug Bridge (ADB) reconnaissance command and a web probe for the path `/geoserver/web/`.

### 3. Emerging n-day Exploitation
- **CVE-2019-11500:** A single event was observed.
- **CVE-2021-3449:** A single event was observed.

### 4. Known-Exploit Exclusions
- **VNC Scanning:** High-volume activity (862+ events) consistent with untargeted, commodity scanning against VNC-related ports (59xx).
- **SSH Scanning & Brute-Force:** Standard activity targeting SSH, characterized by invalid banners and common credential stuffing.
- **ADB Reconnaissance (formerly CAND-20260228-1):** An ADB device fingerprinting command (`echo "$(getprop...)"`) originated from IP `45.135.194.48`. Validation confirmed this IP is on the Spamhaus DROP list, and OSINT verified it belongs to a known malicious actor engaged in widespread, automated scanning. The activity is classified as commodity noise.
- **Network Noise:** A high volume of alerts for truncated packets (3100+ events) were observed, which are indicative of network-level issues or malformed packets, not application-layer exploits.

### 5. Novel Exploit Candidates
*No candidates met the criteria for this category.*

### 6. Suspicious Unmapped Activity to Monitor
- **candidate_id:** CAND-20260228-2
- **classification:** Reconnaissance for Vulnerable Application (GeoServer)
- **novelty_score:** 4
- **confidence:** Medium
- **key evidence:** A single GET request was made to the path `/geoserver/web/` from source IP `216.218.206.69`. OSINT confirms that GeoServer is a high-value target with multiple recent, critical, and actively exploited CVEs. Probing this specific path is a documented reconnaissance technique used as a precursor to launching targeted exploits.
- **provisional flag:** false

### 7. Infrastructure & Behavioral Classification
- **Known-Bad Scanner (ADB):** `45.135.194.48` (AS51396, Pfcloud UG) is part of known malicious infrastructure conducting widespread, automated reconnaissance.
- **Targeted Reconnaissance (GeoServer):** `216.218.206.69` was observed performing targeted application fingerprinting against GeoServer, a known vulnerable web application.
- **General Scanning:** The broader activity originates from common cloud providers like DigitalOcean (AS14061) and Microsoft (AS8075), typical of commodity scanning.

### 8. Analytical Assessment
The investigation was initially degraded by multiple query failures during the discovery phase, which prevented the correlation of leads. Despite these issues, the validation phase successfully analyzed the two primary indicators.

One candidate, an ADB reconnaissance command, was confidently re-classified as commodity noise from a known-bad actor. The second candidate, a web probe against GeoServer, was confirmed to be a targeted reconnaissance attempt against a high-value, vulnerable application. While not an exploit itself, this probe is a known precursor to attacks leveraging recent critical CVEs and warrants monitoring. The overall activity in this window is dominated by noise, but the GeoServer probe represents a credible, though early-stage, threat.

### 9. Confidence Breakdown
- **Overall Confidence:** Medium. The tool failures during initial discovery introduce uncertainty about potential missed correlations.
- **CAND-20260228-2 (GeoServer Recon):** Medium. The activity is clearly reconnaissance, but with only a single probe, the actor's intent to follow up with an exploit is not confirmed.

### 10. Evidence Appendix

**Emerging n-day Item: CVE-2019-11500**
- **source IPs with counts:** Data unavailable from initial query.
- **ASNs with counts:** Data unavailable.
- **target ports/services:** Data unavailable.

**Emerging n-day Item: CVE-2021-3449**
- **source IPs with counts:** Data unavailable from initial query.
- **ASNs with counts:** Data unavailable.
- **target ports/services:** Data unavailable.

**Suspicious Activity: CAND-20260228-2 (GeoServer Recon)**
- **source IPs with counts:** 216.218.206.69 (1 count for the target path)
- **ASNs with counts:** Data unavailable from query results.
- **target ports/services:** 80 (HTTP)
- **paths/endpoints:** `/geoserver/web/`
- **payload/artifact excerpts:** Standard GET request.
- **staging indicators:** None observed.
- **previous-window / 24h checks:** Unavailable.

### 11. Indicators of Interest
- **IP (GeoServer Recon):** `216.218.206.69`
- **Path (GeoServer Recon):** `/geoserver/web/`
- **IP (Commodity ADB Scanner):** `45.135.194.48`
- **TTP (ADB Recon Command):** `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`

### 12. Backend tool issues
- **two_level_terms_aggregated:** This tool failed on two separate occasions during the Candidate Discovery phase. It returned no results in the secondary aggregation buckets when querying the `tanner.parsed_request.path.keyword` and `input.keyword` fields, indicating a probable data mapping or indexing issue.
- **kibanna_discover_query:** This tool failed to find events using the `tanner.parsed_request.path.keyword` field, likely due to the same mapping issue.
- **match_query:** This tool also failed to find results for the `tanner.parsed_request.path` field, which was unexpected given that initial honeypot reports showed the path was observed.