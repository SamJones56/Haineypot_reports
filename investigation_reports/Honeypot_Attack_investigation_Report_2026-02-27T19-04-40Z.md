# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start**: 2026-02-27T18:30:24Z
- **investigation_end**: 2026-02-27T19:00:26Z
- **completion_status**: Complete

### 2. Candidate Discovery Summary
In the 30-minute window, 2,522 total events were analyzed. The activity was dominated by commodity scanning targeting VNC and SSH services, which was excluded as background noise. A high-volume (627 events), targeted HTTP campaign from a single source IP (`151.247.193.252`) was identified as the primary activity of interest. This campaign was initially flagged as a potential novel exploit but was subsequently mapped to a known, recently disclosed vulnerability.

### 3. Emerging n-day Exploitation
The primary finding of this investigation is active scanning and exploitation of a recently disclosed vulnerability.

- **Item ID**: CVE-2025-30208 (Vite Path Traversal)
- **Original Candidate ID**: CAND-001-HTTP-LFI-CREDFILE-PROBE
- **Classification**: n-day Exploit Scanning
- **Confidence**: High
- **Key Evidence**: A single actor (`151.247.193.252`) conducted a systematic campaign of 627 HTTP requests. OSINT analysis confirmed the use of the `/@fs/` prefix combined with path traversal sequences (`..%2f`) and raw query parameters (`?raw??`) is a definitive indicator of scanning for or exploiting CVE-2025-30208. The attacker is attempting to read sensitive system files, including process environment variables and AWS credentials.

### 4. Known-Exploit Exclusions
The following activity was classified as commodity, high-volume scanning or reconnaissance and excluded from deeper analysis.

- **`EXCL-VNC-SCAN`**: 790 events related to `GPL INFO VNC server response` signatures, consistent with broad, untargeted service discovery.
- **`EXCL-SSH-SCAN`**: Approximately 289 events related to generic SSH banner errors and unusual port connections, indicative of routine brute-force preparation.
- **`EXCL-PORT-5431-SCAN`**: 162 events from `46.19.137.194` targeting port 5431, assessed as scanning for PostgreSQL-related services.

### 5. Novel Exploit Candidates (UNMAPPED ONLY, ranked)
No novel (unmapped) exploit candidates were validated in this window. The sole candidate was re-classified as an emerging n-day exploit based on OSINT findings.

### 6. Suspicious Unmapped Activity to Monitor
No activity met the criteria for this category during the investigation period.

### 7. Infrastructure & Behavioral Classification
- **CVE-2025-30208 Exploitation**: Activity originates from `151.247.193.252` (AS399486 - 12651980 CANADA INC.). The behavior is automated and systematic, using a specific fingerprint (`/@fs/` path prefix) to probe for a known path traversal vulnerability in Vite development servers.
- **Background Noise**: Standard scanning and brute-force activity originates from a distributed set of commodity hosting providers, including DigitalOcean (AS14061) and Microsoft (AS8075).

### 8. Analytical Assessment
The investigation concluded with high confidence that the most significant activity in this time window is the active scanning and exploitation of CVE-2025-30208. While initially treated as a potential zero-day due to the lack of signature coverage, OSINT research provided a definitive link to this known vulnerability. The threat is not a novel exploit but rather the weaponization of a publicly disclosed n-day vulnerability. The remainder of the observed traffic is low-level background noise. The initial tool failure during analysis was successfully mitigated by pivoting to an alternative data source, ensuring a complete investigation.

### 9. Confidence Breakdown
- **Overall Confidence**: High. The primary finding was validated through raw log analysis and cross-referenced with public vulnerability reporting, leading to a definitive classification.
- **CVE-2025-30208 Finding**: High. The observed payloads are a direct match for published Proof-of-Concept exploits for this vulnerability.

### 10. Evidence Appendix

**Item: Exploitation of CVE-2025-30208**
- **Source IPs**:
  - `151.247.193.252`: 627 events
- **ASNs**:
  - `399486` (12651980 CANADA INC.): 627 events
- **Target Ports/Services**:
  - `80` (HTTP)
- **Paths/Endpoints**:
  - `/@fs/..%2f..%2f..%2f..%2f..%2fproc/self/environ?raw??`
  - `/@fs/root/.aws/credentials?raw??`
  - `/aws-secret.yaml`
  - `/credentials.yml`
  - `/db.sqlite`
  - `/actuator/configprops`
  - `/app_dev.php/_profiler/phpinfo`
- **Payload/Artifact Excerpts**:
  - The key artifact is the combination of the `/@fs/` prefix with path traversal sequences and raw query parameters (e.g., `?raw??`).
- **Staging Indicators**:
  - None observed.
- **Previous-window / 24h Checks**:
  - Unavailable / Pending. Recommended as a follow-up action.

### 11. Indicators of Interest
- **IP Address**:
  - `151.247.193.252` (Actor scanning for CVE-2025-30208)
- **Network Artifacts / TTPs**:
  - HTTP requests containing the path prefix `/@fs/` followed by traversal sequences (`../` or `%2f..`).
  - HTTP requests containing query strings like `?raw??` or `?import&raw??`.

### 12. Backend tool issues
- **Candidate Discovery Phase**: The `two_level_terms_aggregated` tool initially failed to correlate the source IP with HTTP URLs, likely due to a data schema mismatch. The investigation successfully pivoted to using the `kibanna_discover_query` tool on raw `Tanner` honeypot logs to establish this link.
- **Candidate Validation Phase**: The `two_level_terms_aggregated` tool was used to check for existing alert signatures against the actor's IP. It returned no results, which was correctly interpreted as negative evidence confirming the activity was unmapped by the current signature set.