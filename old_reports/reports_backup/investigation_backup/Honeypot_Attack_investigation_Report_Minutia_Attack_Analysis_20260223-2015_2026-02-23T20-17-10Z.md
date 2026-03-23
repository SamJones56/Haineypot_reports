
**INVESTIGATION REPORT**

**Case ID:** Minutia-Attack-Analysis-20260223-2015
**Date:** 2026-02-23 20:15:37 UTC
**Investigator:** Senior Cyber Threat Investigator

**1.0 Executive Summary**

This investigation was initiated to identify and analyze low-frequency, high-interest attack vectors ("minutia attacks") within the honeypot network over a four-hour period. The investigation successfully identified a malicious actor, **185.177.72.49**, conducting a highly systematic, widespread scanning campaign for file upload vulnerabilities. Despite initial difficulties in retrieving specific event data, a pivot to correlation analysis allowed for the de-anonymization of the actor. Open-source intelligence confirmed the IP is a known malicious scanner. The actor's activity is assessed as a deliberate, automated, and targeted reconnaissance effort to discover specific web application vulnerabilities.

**2.0 Investigation Chronology and Methodology**

The investigation commenced at 16:15:37 UTC and concluded at 20:15:37 UTC on 2026-02-23. The primary objective was to filter out high-volume, automated noise and identify unique or targeted attack patterns.

Initial efforts focused on identifying low-occurrence CVEs. While several rare CVEs were noted (`CVE-2021-41773`, `CVE-2021-42013`), direct queries to retrieve the associated event records failed, indicating a data visibility issue with the tooling for low-volume events.

Recognizing this technical limitation, the investigation pivoted to analyzing anomalous web request URIs captured by the Tanner web honeypot. This proved to be a more effective strategy.

**3.0 Lead Development: Systematic File Upload Probing**

A query of Tanner honeypot data revealed a significant pattern of behavior that stood out from baseline scanning noise.

- **Observation:** A large cluster of distinct URIs, numbering in the dozens, were each requested exactly four times.
- **TTP Analysis:** These URIs consistently targeted endpoints associated with file uploads, data imports, and administrative functions. Examples include `/form/admin/upload`, `/api/v1/import`, `/webhook/api/file`, and `/ioxi.php`.
- **Hypothesis:** The uniformity of the hit count and the thematic consistency of the URIs indicated a single actor systematically scanning for a specific class of vulnerability: unauthenticated or insecure file upload endpoints. This represents a more targeted TTP than generic web scanning.

**4.0 Actor Identification Through Correlation**

With direct event lookup proving unreliable, a broader correlation analysis was performed to identify the source of the URI scanning campaign.

- **Method:** A nested aggregation was used to identify the top source IP addresses interacting with each honeypot type.
- **Finding:** The IP address **185.177.72.49** was identified as the top source of traffic against the Tanner honeypot, registering 1,772 distinct events within the four-hour window. This volume was an order of magnitude higher than the next most active source and was more than sufficient to account for the observed URI scanning.
- **Conclusion:** With high confidence, `185.177.72.49` was identified as the actor responsible for the file upload vulnerability scanning campaign.

**5.0 OSINT Corroboration**

A targeted open-source intelligence query on `185.177.72.49` confirmed its malicious nature.

- The IP is listed on multiple threat intelligence blacklists (AbuseIPDB, Spamhaus, etc.).
- It is associated with a network range (185.177.72.0/24) flagged as "very aggressive."
- Crucially, it has been previously reported for activities directly matching the observed behavior, including being a "Backup File Scanner" and launching attacks against various web applications.

**6.0 Final Conclusion**

This investigation successfully identified a nuanced, low-and-slow attack pattern within a high-volume data environment. The actor at **185.177.72.49** is engaged in a deliberate and automated campaign to discover file upload vulnerabilities across a wide range of common web application endpoints. While the individual probes are low-volume, the overall campaign is systematic and indicates a clear, malicious intent to find exploitable entry points for initial access or malware delivery.

**Confidence Level: High**
