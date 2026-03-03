# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start**: 2026-02-26T03:30:09Z
- **investigation_end**: 2026-02-26T04:00:09Z
- **completion_status**: Partial (degraded evidence)

### 2. Candidate Discovery Summary
The investigation window contained 1,436 total attack events, primarily dominated by commodity network scanning and credential stuffing. Initial analysis flagged low-volume alerts for CVE-2024-14007, but an evidence gap prevented further investigation. Deeper analysis identified three activity clusters: probing for a specific web path (`/nice%20ports%2C/Tri%6Eity.txt%2ebak`), requests to a DigitalOcean metrics API, and low-volume probes against SIP and ICS (IEC104) protocols. Subsequent validation reclassified the web and SIP probes as known Nmap/SIPVicious scanning noise. The DigitalOcean API activity was confirmed as scanning for a known n-day vulnerability, and the ICS activity remains suspicious but unconfirmed due to tool failures.

### 3. Emerging n-day Exploitation
- **candidate_id**: droplet_id_metrics_probe
- **classification**: DigitalOcean API BFLA Vulnerability Scanning (n-day)
- **novelty_score**: 7
- **confidence**: High
- **key_evidence**: Multiple (45) GET requests from a single source IP (`167.71.255.16`) to a specific DigitalOcean metrics API endpoint (`/v1/metrics/droplet_id/553005910`). The activity targeted the cloud metadata IP `169.254.169.254`, which is indicative of an attempt to exploit a known Broken Function Level Authorization (BFLA) vulnerability from within a compromised cloud environment.
- **provisional_flag**: false

### 4. Known-Exploit Exclusions
- **Nmap Web Server Fingerprinting**: Activity initially flagged as `trinity_probe_01` was positively identified as a standard web server fingerprinting probe used by the Nmap network scanner. The key indicator was requests for the path `/nice%20ports%2C/Tri%6Eity.txt%2ebak`.
- **SIP Username Enumeration**: Activity flagged as `SIP_probe_monitor` was identified as a common username/extension enumeration technique (`sip:nm`) used by SIP vulnerability scanners like SIPVicious. This was linked to the same source IPs as the Nmap scanning.
- **Commodity Network Scanning**: High-volume, low-sophistication network traffic anomalies, primarily identified by SURICATA signatures like `STREAM 3way handshake SYN resend` and `SSH invalid banner`.
- **Commodity Credential Stuffing**: Standard brute-force login attempts against various services using common credential lists (e.g., user: `root`, `admin`; pass: `123`, `admin`).

### 5. Novel Exploit Candidates (UNMAPPED ONLY, ranked)
*No novel exploit candidates were validated in this investigation window. The primary candidate was downgraded to a known exclusion.*

### 6. Suspicious Unmapped Activity to Monitor
- **candidate_id**: ICS_IEC104_probe
- **classification**: (Provisional) Unconfirmed ICS/SCADA Protocol Probing
- **novelty_score**: 3
- **confidence**: Low
- **key_evidence**: Initial honeypot data reported 3 events targeting the IEC 104 protocol, a sensitive SCADA service. However, attempts to retrieve the raw event logs for inspection failed. Due to the sensitive nature of the target protocol, this activity is flagged for monitoring despite the evidence gap.
- **provisional_flag**: true

### 7. Infrastructure & Behavioral Classification
- **DigitalOcean BFLA Scanning**: Targeted scanning for a known cloud vulnerability originating from a single IP (`167.71.255.16`) within the DigitalOcean (AS14061) network. The behavior suggests an actor using a compromised cloud host to find other vulnerable instances.
- **Commodity Reconnaissance**: Coordinated, multi-protocol scanning from multiple IPs (`185.242.226.46`, `24.199.80.236`) using well-known signatures of standard tools like Nmap and SIPVicious.
- **Unconfirmed ICS Probing**: Low-volume activity targeting the IEC104 protocol. Actor and intent could not be determined due to failed data retrieval.

### 8. Analytical Assessment
The investigation successfully identified and triaged a clear instance of n-day vulnerability scanning targeting a known DigitalOcean API flaw. This activity represents the most significant threat observed. The workflow correctly de-prioritized what initially appeared to be a novel reconnaissance campaign by identifying it as common Nmap scanner noise.

However, the investigation's completeness is partial. A key evidence gap prevented analysis of alerts for `CVE-2024-14007`. Furthermore, multiple tool failures blocked the retrieval of raw logs for SIP and IEC104 activity, leading to a provisional and low-confidence assessment for the ICS-related probes.

### 9. Confidence Breakdown
- **droplet_id_metrics_probe (Emerging n-day)**: **High**. The classification is strongly supported by specific log evidence, successful validation queries, and corroborating OSINT regarding the BFLA vulnerability.
- **ICS_IEC104_probe (Suspicious to Monitor)**: **Low (Provisional)**. The classification is based solely on an initial aggregated count from a honeypot sensor. The inability to retrieve and inspect the raw events due to a tool failure prevents any definitive conclusion.
- **Overall Investigation Confidence**: **Medium**. While the highest-priority finding was validated with high confidence, multiple tool failures created evidence gaps that left other lines of inquiry incomplete and degraded the overall integrity of the analysis.

### 10. Evidence Appendix
**Emerging n-day: droplet_id_metrics_probe**
- **Source IPs**: `167.71.255.16` (45 counts)
- **ASNs**: 14061 (DigitalOcean, LLC)
- **Target Ports/Services**: 80 (HTTP)
- **Paths/Endpoints**: `/v1/metrics/droplet_id/553005910`
- **Payload/Artifact Excerpts**: None (HTTP GET request)
- **Previous-window / 24h checks**: Not performed; OSINT confirms the vulnerability is publicly known and recent.

**Suspicious: ICS_IEC104_probe**
- **Source IPs**: Unavailable (tool failure)
- **ASNs**: Unavailable
- **Target Ports/Services**: IEC104
- **Paths/Endpoints**: N/A
- **Payload/Artifact Excerpts**: Unavailable (tool failure)
- **Previous-window / 24h checks**: Unavailable

### 11. Indicators of Interest
- `167.71.255.16` (IPv4 Address): Source of scanning for DigitalOcean BFLA vulnerability.
- `/v1/metrics/droplet_id/` (URL Path): URI pattern indicating scanning for DigitalOcean BFLA vulnerability.

### 12. Backend tool issues
- **top_src_ips_for_cve**: A query for source IPs related to `CVE-2024-14007` returned no results, despite initial data showing 2 alerts. This blocked investigation into the CVE.
- **suricata_lenient_phrase_search**: The query for `sip:nm` failed due to a backend database configuration (`fielddata` disabled on the `message` field), preventing retrieval of raw logs for the SIP probe validation.
- **kibanna_discover_query**: The query for `appproto.keyword` as `iec104` returned zero results, contradicting initial honeypot data showing 3 events and blocking validation of the ICS probe.