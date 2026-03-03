# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start**: 2026-02-27T17:30:18Z
- **investigation_end**: 2026-02-27T18:00:18Z
- **completion_status**: Partial (degraded evidence)
  - *Note: A backend query tool (`two_level_terms_aggregated`) failed to correlate source IPs to all HTTP URLs, requiring a pivot to more targeted queries. This did not block validation of the primary candidate but limited broad correlation.*

### 2. Candidate Discovery Summary
In the last 30 minutes, 2004 attacks were observed. The majority of this activity was commodity scanning noise targeting VNC (762+ events) and SSH services, which has been excluded. A single high-confidence candidate (`CAND-01`) was identified, characterized by targeted, unmapped reconnaissance against a web application framework, likely GitLab.

### 3. Known-Exploit Exclusions
- **Commodity VNC scanning**: High volume of events (762) for signature 'GPL INFO VNC server response' on ports 5901/5902.
- **Commodity SSH scanning**: High volume of events for multiple SSH-related signatures, including 'SURICATA SSH invalid banner'.
- **Commodity RDP scanning**: Activity mapped to signature 'ET SCAN MS Terminal Server Traffic on Non-standard Port'.

### 4. Novel Exploit Candidates
---
**1. CAND-01**
- **classification**: Targeted Reconnaissance / Application Fingerprinting
- **novelty_score**: 5
- **confidence**: High
- **key evidence**: A single source IP (`152.42.255.97`) was observed making persistent `GET` requests for a specific set of JavaScript assets (webpack chunks) related to user sessions (e.g., `...pages.sessions.new...js`). All requests used a `Go-http-client/1.1` User-Agent, indicating an automated tool. This activity is not associated with any known signatures or CVEs in the dataset.
- **provisional flag**: true

---

### 5. Suspicious Unmapped Activity to Monitor
- None identified.

### 6. Infrastructure & Behavioral Classification
- **CAND-01**: The attacker infrastructure is hosted on DigitalOcean (ASN 14061). The behavior is consistent with an automated script (`Go-http-client/1.1`) performing methodical fingerprinting of a specific web application, identified through webpack asset paths as likely being GitLab. The activity is purely reconnaissance at this stage, with no observed exploit delivery.

### 7. Analytical Assessment
The investigation successfully filtered high-volume commodity scanning noise to isolate a single, high-confidence candidate, **CAND-01**. This activity represents a targeted reconnaissance campaign from the IP address `152.42.255.97` to fingerprint specific GitLab instances.

OSINT analysis confirms that while the general target (GitLab) has known critical vulnerabilities (e.g., CVE-2023-7028 Account Takeover), this specific reconnaissance TTP (the combination of URI paths and User-Agent) is not publicly documented. Therefore, CAND-01 is classified as a novel reconnaissance pattern, likely preceding an attempt to exploit a known n-day vulnerability.

Confidence in this assessment is high, despite a minor tool failure during the investigation which was successfully mitigated with alternative queries.

### 8. Confidence Breakdown
- **CAND-01**: High. The evidence of targeted reconnaissance is consistent, specific, and persistent over at least one hour.
- **Overall Investigation**: High. The primary candidate was clearly identified and validated, and the impact of the tool failure was minimal.

### 9. Evidence Appendix
---
**Candidate: CAND-01**
- **source IPs with counts**:
  - `152.42.255.97`: 138 events
- **ASNs with counts**:
  - `14061` (DigitalOcean, LLC): All associated events
- **target ports/services**:
  - `80` (HTTP)
- **paths/endpoints**:
  - `/`
  - `/assets/webpack/commons~pages.ldap.omniauth_callbacks~pages.omniauth_callbacks~pages.sessions~pages.sessions.new.432e20dc.chunk.js`
  - `/assets/webpack/main.a66b6c66.chunk.js`
  - `/assets/webpack/pages.sessions.new.6dbf9c97.chunk.js`
  - `/assets/webpack/runtime.9fcb75d4.bundle.js`
- **payload/artifact excerpts**:
  - `http.http_user_agent`: "Go-http-client/1.1"
  - `http.http_method`: "GET"
- **staging indicators**:
  - None observed.
- **previous-window / 24h checks**:
  - Activity was confirmed to be present and identical in the 30-minute window prior to this investigation period (`17:00:18Z - 17:30:18Z`).

---
### 10. Indicators of Interest
- **IP Address**: `152.42.255.97`
- **User-Agent**: `Go-http-client/1.1`
- **URI Path Contains**: `/assets/webpack/pages.sessions.new`

### 11. Backend tool issues
- **Failed Tool**: `two_level_terms_aggregated`
  - **Issue**: The query failed to generate correlations between the primary field (`src_ip.keyword`) and the secondary field (`http.url.keyword`), returning empty secondary buckets. This prevented an immediate broad overview of which IPs were targeting which URLs.