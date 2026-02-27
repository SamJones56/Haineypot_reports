# Zero-Day Candidate Triage Report

### **1. Investigation Scope**
- **investigation_start:** 2026-02-27T16:30:17Z
- **investigation_end:** 2026-02-27T17:00:18Z
- **completion_status:** Complete

### **2. Candidate Discovery Summary**
The investigation analyzed 1,479 events within the 30-minute window. Initial activity was dominated by commodity VNC and SSH scanning noise. A single probe for a `/.env` file on a web honeypot was isolated from this noise and selected as the primary candidate for validation. Subsequent analysis validated this activity and attributed it to a known, widespread reconnaissance campaign.

### **3. Emerging n-day Exploitation**
- **candidate_id:** CAND-001
- **classification:** Known Reconnaissance Campaign ('.env' file exposure)
- **summary:** Activity originating from 34.158.168.101 was validated as part of a recently reported, widespread scanning campaign targeting exposed `.env` configuration files. This actor combines web probes on ports 80, 443, 8080, and 8443 with passive OS and application fingerprinting. OSINT confirms this IP is a known malicious scanner active since early February 2026, engaged in this specific campaign. While the technique is not new (related to vulnerabilities like CVE-2017-16894), the campaign itself is recent and active.

### **4. Known-Exploit Exclusions**
- **Commodity VNC Scanning:** Excluded due to high volumes of the "GPL INFO VNC server response" signature (788 events) and correlation with the dated vulnerability CVE-2006-2369. This activity is consistent with background internet noise.
- **Commodity SSH Scanning:** Excluded based on common enumeration signatures such as "SURICATA SSH invalid banner" (165 events) and "ET INFO SSH session in progress on Unusual Port" (67 events). This represents standard, non-targeted scanning.

### **5. Novel Exploit Candidates**
No candidates were classified as novel. The primary candidate (`CAND-001`) was declassified from novel to a known scanning campaign based on definitive OSINT findings.

### **6. Infrastructure & Behavioral Classification**
- **'.env' Scanning Campaign (CAND-001):** The actor (34.158.168.101) uses infrastructure hosted by Google LLC (AS396982). The behavior is automated, multi-stage reconnaissance, involving broad web port scanning, targeted path probing (`/.env`), and passive system fingerprinting (P0f, Fatt) to identify vulnerable targets at scale.
- **VNC/SSH Scanning:** Activity originates from a distributed set of sources, with DigitalOcean, LLC (AS14061) being the most prominent ASN. The behavior is low-sophistication, high-volume, opportunistic port and service scanning.

### **7. Analytical Assessment**
The investigation successfully triaged the observed activity. Initial tool failures during the discovery phase created an evidence gap, preventing the correlation of the `/.env` probe with a source IP. However, the validation phase successfully overcame this gap using alternative tools, enabling a full analysis. The final OSINT enrichment was critical, providing the necessary context to re-classify the candidate from a potentially novel threat to part of a known, ongoing reconnaissance campaign. The workflow's conclusion is well-supported by the correlated evidence.

### **8. Confidence Breakdown**
- **Overall Confidence:** High. Despite initial data access issues, the validation and OSINT phases successfully resolved all ambiguities.
- **CAND-001 Classification Confidence:** High. The internal evidence strongly correlates with public threat intelligence reports, confirming the activity is part of a known campaign.

### **9. Evidence Appendix**

**CAND-001: '.env' Scanning Campaign**
- **source IPs with counts:**
  - 34.158.168.101: (Associated with 1010 events in the timeframe)
- **ASNs with counts:**
  - 396982 (Google LLC): (Count not isolated, but associated with the source IP)
- **target ports/services:**
  - 80/tcp (HTTP)
  - 443/tcp (HTTPS)
  - 8080/tcp (HTTP-alt)
  - 8443/tcp (HTTPS-alt)
- **paths/endpoints:**
  - `/.env`
- **payload/artifact excerpts:**
  - `GET /.env HTTP/1.1`
- **staging indicators:**
  - Extensive passive fingerprinting (595 P0f events, 89 Fatt events) from the source IP indicates pre-attack reconnaissance.
- **previous-window / 24h checks:**
  - Unavailable.

### **10. Indicators of Interest**
- **IP Address:** 34.158.168.101
- **HTTP Path:** `/.env`

### **11. Backend tool issues**
- **`two_level_terms_aggregated`:** This tool failed during the discovery phase when attempting to correlate the `http.request.uri.keyword` `/.env` with a source IP. The query returned no results.
- **`kibanna_discover_query`:** This tool also failed to find events for the `/.env` path during discovery. The failures suggest that the web honeypot data (from Tanner) may not be accessible via the same fields or indices as the general event data lake. These issues were resolved by the `CandidateValidationAgent` using the more specific `web_path_samples` tool.