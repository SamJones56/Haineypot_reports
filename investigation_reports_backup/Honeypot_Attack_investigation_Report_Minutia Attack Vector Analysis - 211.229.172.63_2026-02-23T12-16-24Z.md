### INVESTIGATION REPORT

**Case ID:** MINUTIA-2024-05-20-01
**Status:** Active
**Investigator:** Senior Threat Investigator
**Priority:** High

---

#### **1.0 Executive Summary**

This investigation focuses on identifying and analyzing low-volume, high-interest attack vectors observed over the past four hours. The objective is to move beyond high-frequency, automated scanning activity and isolate attackers or methodologies that demonstrate specificity, potential novelty, or targeted intent. The investigation successfully identified a lead involving targeted probing for specific web vulnerabilities, which was selected for deeper analysis.

#### **2.0 Investigation Scope and Timeframe**

*   **Objective:** Identify and analyze minutia attacks, defined as activity with low frequency but high potential interest due to unusual methods, targets, or payloads.
*   **Start Time (UTC):** 2024-05-20T10:04:18.995Z
*   **End Time (UTC):** 2024-05-20T14:04:18.995Z
*   **Data Source:** Live Honeypot Network Queries

---

#### **3.0 Initial Baseline and Environmental Scan**

To distinguish anomalous activity from background noise, a baseline of the overall threat landscape within the operational timeframe was established.

*   **Total Attack Volume:** 13,858 events recorded.
*   **Top Attacker Countries:** United States (3,261 events), Germany (1,154 events), India (749 events).
*   **Top Attacker ASNs:** GOOGLE-CLOUD-PLATFORM (1,494 events), AS-CHOOPA (1,133 events), DIGITALOCEAN-ASN (1,029 events).
*   **Most Targeted Ports:** 23/tcp (2,168 events), 80/tcp (1,167 events), 445/tcp (872 events).
*   **Common Alert Signatures:** "GPL TELNET Bad Login" (1,061 events), "SURICATA Applayer Detect protocol only one direction" (968 events).
*   **Common CVEs:** CVE-2017-0144 (ETERNALBLUE/MS17-010) was the most prominent.

This baseline confirms that the majority of traffic is automated, opportunistic scanning and brute-force activity targeting common services (Telnet, HTTP, SMB) originating from large cloud providers. This is the "noise" that the investigation aims to filter out.

---

#### **4.0 Lead Development: Identification of Anomalous URI Probing**

While analyzing web-based activity, specific and unusual Uniform Resource Identifier (URI) requests were isolated that deviate significantly from generic scanning.

**4.1 Initial Finding**

A query for web requests (`tanner_unifrom_resource_search`) revealed several low-frequency URIs. The following entries were flagged as leads due to their specificity, suggesting an actor looking for more than just a generic web server:

*   `/solr/admin/info/system` (1 event)
*   `/admin/controller/extension/extension/path` (1 event)
*   `/.env` (16 events)
*   `/wp-content/plugins/seoplugins/mar.php` (1 event)
*   `/boaform/admin/formLogin` (1 event)

The request for `/solr/admin/info/system` was selected as the primary lead for hypothesis testing, as it indicates a targeted probe for an Apache Solr instance, a popular open-source search platform. Unauthenticated access to this endpoint can reveal extensive configuration details, version information, and potentially lead to further exploitation.

**4.2 Hypothesis Formulation**

*   **Hypothesis:** An actor is conducting targeted reconnaissance to identify and enumerate Apache Solr administrative interfaces for potential exploitation. The low volume suggests this is not part of a widespread, generic scanning campaign but rather a more focused effort.

---

#### **5.0 Hypothesis Testing and Pivotal Analysis**

To validate the hypothesis, the investigation pivoted to analyze all activities associated with the source IP that triggered the Apache Solr probe.

**5.1 Correlating Actor to Activity**

A discovery query was executed to identify the actor behind the `/solr/admin/info/system` request.

*   **Source IP:** 211.229.172.63
*   **Geolocation:** Seoul, South Korea
*   **ASN:** AS4766 - KT Corporation

**5.2 Deep Dive on Actor 211.229.172.63**

A subsequent query was performed to retrieve all events originating from `211.229.172.63` within the investigation window. The results revealed a clear pattern of targeted web vulnerability probing. The actor made a total of four (4) requests, each for a different, specific vulnerability or administrative interface:

1.  `/solr/admin/info/system`: Probing for Apache Solr.
2.  `/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=cat..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd&curpath=/&currentsetting.htm=1`: Attempting to exploit a command injection vulnerability in Netgear routers.
3.  `/boaform/admin/formLogin`: Probing for the login page of a Boa web server, commonly used in embedded devices like routers and cameras.
4.  `/TP/public/index.php`: Probing for a ThinkPHP installation.

**5.3 OSINT Correlation**

A search was conducted to determine if `211.229.172.63` is a known malicious actor. OSINT data confirms that this IP address has been repeatedly reported for malicious activities, including web scanning, SSH brute-force attacks, and application-level attacks. This corroborates the observed behavior.

---

#### **6.0 Analytical Conclusion**

The evidence strongly supports the hypothesis. The activity from `211.229.172.63` is not random noise. It is a deliberate, albeit low-volume, reconnaissance effort targeting multiple, distinct web application and embedded device vulnerabilities.

*   **Nature of Activity:** Targeted, automated reconnaissance. The actor is using a tool or script to probe for a curated list of high-value vulnerabilities rather than scanning the entire internet for a single flaw.
*   **Operational Sophistication:** Low to Moderate. The techniques themselves (sending GET requests) are simple, but the selection of targets implies a more sophisticated understanding of valuable vulnerabilities beyond common WordPress or Drupal exploits.
*   **Potential Intent:** The actor is likely profiling the honeypot to identify specific, exploitable services. If a vulnerable service were found, the next stage would likely involve exploitation, payload delivery, or credential theft.
*   **Confidence Level:** High. The combination of diverse, specific URI probes from a single source IP provides clear evidence of targeted reconnaissance.

This actor represents a higher-quality lead than a typical high-volume scanner because their intent is more focused, and their TTPs indicate a goal-oriented approach to finding specific, valuable targets.