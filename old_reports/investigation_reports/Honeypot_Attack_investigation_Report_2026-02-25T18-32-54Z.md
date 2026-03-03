# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start:** 2026-02-25T18:00:07Z
- **investigation_end:** 2026-02-25T18:30:07Z
- **completion_status:** Inconclusive
- **Degradation Notes:** The investigation was significantly impaired by backend tool failures. Multiple queries against the `http.url` and `src_ip` fields failed because `fielddata` is disabled on text fields in the backend datastore. This blocked the validation and correlation of the primary candidate (CAND-20260225-1), preventing the identification of source IPs and the retrieval of raw event logs.

### 2. Candidate Discovery Summary
The 30-minute window saw 1,792 attacks, dominated by high-volume scanning of VNC (ports 5902-5907) and SSH (ports 22, 2233) services, alongside commodity credential stuffing. The primary area of interest was a set of 150 events captured by the Tanner web honeypot, which revealed reconnaissance activity using path traversal techniques to locate sensitive files such as `.aws/credentials`, `/proc/self/environ`, and `.env`.

### 3. Emerging n-day Exploitation
- **CVE-2025-30208:**
  - **Description:** Activity matching signatures for CVE-2025-30208 was detected.
  - **Count:** 12 events.
  - **Confidence:** High (Signature-based).

### 4. Known-Exploit Exclusions
- **Local File Inclusion / Path Traversal Scanning (CAND-20260225-1):**
  - **Description:** Path traversal attempts targeting common sensitive files (`/proc/self/environ`, `.aws/credentials`, `.env`) were observed in the Tanner honeypot. OSINT validation confirms this is a classic, well-documented, and widespread technique for LFI reconnaissance, not indicative of a novel exploit.
  - **Evidence:** Tanner honeypot logs showing multiple URI paths with traversal sequences. OSINT search results confirmed the public nature of these attack patterns.
  - **Confidence:** High.
- **VNC/RDP Scanning:**
  - **Description:** Widespread, non-targeted scanning for open VNC and RDP services.
  - **Evidence:** 106 events for "GPL INFO VNC server response" and 63 events for "ET SCAN MS Terminal Server Traffic on Non-standard Port".
  - **Confidence:** High.
- **SSH Scanning & Brute-Force:**
  - **Description:** Commodity scanning and brute-force attempts against SSH.
  - **Evidence:** 115 events for "SURICATA SSH invalid banner" and a high volume of common credential attempts (e.g., user 'root').
  - **Confidence:** High.
- **Miscellaneous Low-Volume CVE Activity:**
  - **Description:** Very low counts of older, well-known CVEs were observed, consistent with background noise.
  - **Evidence:** CVE-2021-3449 (3 events), CVE-2019-11500 (2 events), CVE-2020-5410 (2 events).
  - **Confidence:** High.

### 5. Novel Exploit Candidates
*No unmapped novel candidates were validated in this window.* The primary candidate identified during discovery (CAND-20260225-1) was re-classified as known reconnaissance activity following OSINT validation.

### 6. Suspicious Unmapped Activity to Monitor
*No items met the criteria for this category.*

### 7. Infrastructure & Behavioral Classification
- **Infrastructure:** Activity primarily originated from commercial hosting and cloud providers, including DigitalOcean (AS14061), UCLOUD (AS135377), Unmanaged Ltd (AS47890), Pfcloud (AS51396), and Hetzner (AS24940).
- **Behavior:** The observed behavior is classified as high-volume, opportunistic, and non-targeted scanning. This includes reconnaissance for common vulnerabilities (LFI/Path Traversal), protocol-specific scanning (VNC, SSH), and low-sophistication credential stuffing.

### 8. Analytical Assessment
The investigation window was dominated by automated, commodity-level scanning and reconnaissance activity. A small amount of emerging n-day activity for **CVE-2025-30208** was detected.

The most notable unmapped activity, a series of path traversal attempts (CAND-20260225-1), was successfully identified by honeypot telemetry. However, OSINT validation confirmed this is a well-established and common LFI scanning technique, not a novel exploit.

**Crucially, the analytical process was inconclusive.** Backend query failures prevented the correlation of the path traversal attempts with their source IPs or any other metadata. While we can classify the *type* of attack as known, we were unable to fully investigate its scope or attribute it to specific actors due to this evidence gap. The assessment relies on degraded evidence.

### 9. Confidence Breakdown
- **Overall Confidence:** Medium. While individual components like signatures and OSINT findings are high confidence, the inability to perform deeper validation on key evidence due to tool failures reduces the overall confidence in the completeness of the investigation.
- **CVE-2025-30208:** High. Based on signature match.
- **Path Traversal (CAND-20260225-1) as Known Activity:** High. Based on definitive OSINT results mapping it to a classic technique.

### 10. Evidence Appendix
**Emerging n-day: CVE-2025-30208**
- **source IPs with counts:** Unavailable.
- **ASNs with counts:** Unavailable.
- **target ports/services:** Unavailable.
- **paths/endpoints:** Unavailable.
- **payload/artifact excerpts:** Unavailable.
- **previous-window / 24h checks:** Not performed.

**Known Exploit: LFI / Path Traversal Scanning (CAND-20260225-1)**
- **source IPs with counts:** Unavailable due to backend query failure.
- **ASNs with counts:** Unavailable due to backend query failure.
- **target ports/services:** HTTP (port not specified).
- **paths/endpoints:**
  - `/..%2f..%2f..%2f..%2f..%2f..%2fhome/ubuntu/.aws/credentials` (1 hit)
  - `/..%2f..%2f..%2f..%2f..%2f..%2fproc/self/environ` (1 hit)
  - `/..%2f..%2f..%2f..%2f..%2f..%2froot/.aws/credentials` (1 hit)
  - `/../../../../../../../app/.env` (1 hit)
- **payload/artifact excerpts:** The URI paths themselves are the primary artifacts.
- **staging indicators:** None observed.
- **previous-window / 24h checks:** Unavailable due to backend query failure.

### 11. Indicators of Interest
- **Path Traversal Reconnaissance URIs:**
  - `*/..%2f..%2f..%2f..%2f..%2f..%2fhome/ubuntu/.aws/credentials`
  - `*/..%2f..%2f..%2f..%2f..%2f..%2fproc/self/environ`
  - `*/..%2f..%2f..%2f..%2f..%2f..%2froot/.aws/credentials`
  - `*/../../../../../../../app/.env`

### 12. Backend tool issues
- **Failed Tools:**
  - `two_level_terms_aggregated`
  - `match_query`
  - `kibanna_discover_query`
  - `suricata_lenient_phrase_search`
- **Reason:** Multiple queries failed with a `400 Bad Request` status. The root cause was `illegal_argument_exception` because `fielddata` is disabled by default on text fields like `http.url` and `src_ip` in the backend datastore. This prevented aggregations and some search types, blocking critical validation steps.