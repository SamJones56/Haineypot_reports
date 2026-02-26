# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start**: 2026-02-26T05:00:07Z
- **investigation_end**: 2026-02-26T05:30:08Z
- **completion_status**: Partial (degraded evidence)
- **Degradation Note**: The investigation's ability to profile attacker activity was hindered by multiple backend tool failures. Deep-dive queries during discovery (`kibanna_discover_query`, `top_src_ips_for_cve`, `top_dest_ports_for_cve`) failed to return data for initial leads. During validation, the `two_level_terms_aggregated` tool repeatedly failed, preventing a full analysis of other activities conducted by the identified attacker IPs.

### 2. Candidate Discovery Summary
A total of 1,643 events were analyzed in the 30-minute window. The initial triage identified three main areas of interest: active exploitation alerts for CVE-2025-55182, a highly anomalous URI path (`/developmentserver/metadatauploader`), and common reconnaissance probes for exposed Docker APIs (`/containers/json`). The majority of other activity was attributed to commodity scanning and network noise.

### 3. Emerging n-day Exploitation
- **Item**: CVE-2025-55182 (React2Shell) Exploitation
- **Classification**: Emerging N-day Exploitation
- **Confidence**: High
- **Summary**: Confirmed active exploitation of CVE-2025-55182, a critical (CVSS 10.0) pre-authentication RCE vulnerability in React Server Components. All events originated from a single source IP and triggered a specific high-fidelity signature. OSINT confirms this CVE is recently disclosed, listed in the CISA KEV catalog, and under active exploitation in the wild.

### 4. Known-Exploit Exclusions
- **Item 1**: SAP NetWeaver RCE Scanning (CVE-2025-31324)
  - **Classification**: Known Exploit (Novel to Environment)
  - **Summary**: Activity targeting the URI `/developmentserver/metadatauploader` was identified. OSINT and event analysis confirm this is scanning for CVE-2025-31324, a critical (CVSS 10.0) RCE in SAP NetWeaver.
  - **Intelligence Gap Note**: This activity was initially flagged as a novel candidate because it did not trigger any specific CVE or SAP-related signatures. It was only identified through generic `Zmap User-Agent` alerts. This represents a detection gap for a known, critical threat.

- **Item 2**: Docker API Probing
  - **Classification**: Commodity Noise
  - **Summary**: Reconnaissance activity targeting the URI `/containers/json` was identified. This is a well-known, non-targeted technique used by automated scanners to find misconfigured, publicly exposed Docker daemon APIs. The source IP exhibited short-lived, multi-port scanning behavior consistent with background noise.

- **Item 3**: General Scanning and Noise
  - **Summary**: The remainder of excluded activity consisted of widespread, low-value scanning targeting VNC, SSH, and RDP, as well as generic protocol anomalies and malformed packets.

### 5. Infrastructure & Behavioral Classification
- **193.32.162.28**: Engaged in focused, sustained (28-minute) scanning specifically targeting a high-value vulnerability (CVE-2025-55182), indicating a targeted exploitation campaign.
- **52.165.88.92**: Conducted mass scanning using Zmap tooling, indicative of a broad, opportunistic search for vulnerable SAP instances (CVE-2025-31324).
- **119.29.163.4**: Exhibited short-lived (2-minute), multi-port scanning behavior typical of automated, non-targeted scanners looking for common misconfigurations like exposed Docker APIs.

### 6. Analytical Assessment
The investigation confirmed one instance of high-priority, emerging n-day exploitation: active scanning and exploitation attempts against CVE-2025-55182 (React2Shell).

A second critical vulnerability, CVE-2025-31324 (SAP NetWeaver RCE), was also observed being actively scanned for. This finding highlights a significant intelligence gap, as the activity was not detected by specific signatures and was only found due to its anomalous URI path.

The remainder of the observed activity was confidently classified as commodity background noise.

The assessment is partially degraded. Due to repeated tool failures, a full profile of the attackers' TTPs could not be constructed, limiting our understanding of their complete toolset and other potential targets.

### 7. Confidence Breakdown
- **Overall Confidence**: High confidence in the classification of the primary findings. Medium confidence in the completeness of the investigation due to evidence gaps caused by tool failures.
- **CVE-2025-55182 Finding**: High. Based on direct signature matches, consistent attacker behavior, and strong OSINT corroboration.
- **CVE-2025-31324 Finding**: High. The URI path is a definitive indicator for this known exploit, confirmed via OSINT.
- **Docker API Probe Finding**: High. The URI and attacker behavior are characteristic of well-known commodity scanners.

### 8. Evidence Appendix
- **Item**: Emerging N-day: CVE-2025-55182 (React2Shell)
  - **Source IPs**: `193.32.162.28` (6 events)
  - **ASNs**: Unavailable
  - **Target Ports/Services**: `8009`
  - **Paths/Endpoints**: `/`, `/_next`, `/api`, `/_next/server`, `/app`, `/api/route`
  - **Payload/Artifact Excerpts**: Signature match on `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
  - **Staging Indicators**: None observed
  - **Previous-window / 24h Checks**: Unavailable

- **Item**: Known Exploit: CVE-2025-31324 (SAP RCE)
  - **Source IPs**: `52.165.88.92` (4 events)
  - **ASNs**: Unavailable
  - **Target Ports/Services**: `80`, `33948`
  - **Paths/Endpoints**: `/developmentserver/metadatauploader`
  - **Payload/Artifact Excerpts**: `GET` request. Related signature: `ET SCAN Zmap User-Agent (Inbound)`
  - **Staging Indicators**: None observed
  - **Previous-window / 24h Checks**: Unavailable

### 9. Indicators of Interest
- **IP**: `193.32.162.28` (Targeting CVE-2025-55182)
- **IP**: `52.165.88.92` (Scanning for CVE-2025-31324)
- **CVE**: `CVE-2025-55182`
- **CVE**: `CVE-2025-31324`
- **URI**: `/developmentserver/metadatauploader`

### 10. Backend tool issues
The following backend tools failed during the investigation, leading to degraded evidence and blocked analysis paths:
- `kibanna_discover_query`: Failed during the discovery phase, preventing deep-dive analysis of the initial candidate.
- `top_src_ips_for_cve`: Failed during the discovery phase.
- `top_dest_ports_for_cve`: Failed during the discovery phase.
- `two_level_terms_aggregated`: Failed repeatedly during the validation phase for multiple attacker IPs, preventing a full analysis of their associated activities and TTPs.