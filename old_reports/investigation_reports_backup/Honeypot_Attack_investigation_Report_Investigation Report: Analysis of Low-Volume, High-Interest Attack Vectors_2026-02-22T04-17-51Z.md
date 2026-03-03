# Investigation Report: Analysis of Low-Volume, High-Interest Attack Vectors

## 1.0 Executive Summary

This report details the findings of an investigation into low-volume, high-interest attack vectors observed on the honeypot network. The investigation focused on identifying and analyzing attacks that deviate from the baseline of common, high-volume attacks, such as SSH brute-forcing and broad-spectrum port scanning. The goal was to uncover more nuanced and potentially more sophisticated threats.

The investigation identified a targeted reconnaissance campaign against Apache Solr instances. This campaign was characterized by its low volume of traffic, the use of a specific user-agent, and the enumeration of common Solr administration URLs. While no specific CVEs were directly associated with this activity in the honeypot logs, the observed behavior is a clear precursor to an attempt to exploit a known vulnerability or misconfiguration in Apache Solr.

This report will detail the methodology used to identify this attack, the evidence gathered, and an analysis of the attacker's tactics, techniques, and procedures (TTPs).

## 2.0 Investigation Details

### 2.1 Timeframe

*   **Start Time (UTC):** 2026-02-22T00:15:28Z
*   **End Time (UTC):** 2026-02-22T04:15:28Z

### 2.2 Methodology

The investigation followed a structured methodology to identify and analyze low-volume, high-interest attacks:

1.  **Baseline Establishment:** The first step was to establish a baseline of "normal" activity on the honeypot network for the specified timeframe. This involved analyzing the total number of attacks, the top attacking countries, source IPs, ASNs, targeted ports, and alert signatures.
2.  **Lead Identification:** Once the baseline was established, the focus shifted to identifying leads that deviated from the norm. This included looking for attacks on unusual ports, with rare alert signatures, or exhibiting other anomalous characteristics.
3.  **Hypothesis Development and Testing:** For each lead, a hypothesis was developed and then tested using more specific queries and analysis.
4.  **Targeted OSINT:** Open-source intelligence (OSINT) was used to enrich the data and to correlate findings with known attack patterns and vulnerabilities.
5.  **Reporting:** The final step was to compile the findings into a formal investigation report.

## 3.0 Findings

### 3.1 Baseline Analysis

A baseline of activity for the 4-hour investigation window was established, revealing the following:

*   **Total Attacks:** 17,720
*   **Top Attacking Countries:** United States, Australia, India, Germany, Romania
*   **Top Targeted Ports:** 22 (SSH), 2323 (Telnet), 23 (Telnet), 445 (SMB), 5902 (VNC)
*   **Top Alert Signatures:** Predominantly related to SSH, VNC, and blocklisted IPs.

This baseline represents the "background noise" of the internet, with the vast majority of attacks being automated scanning and brute-force attempts against common services.

### 3.2 Lead Identification: Unusual Port Activity

A review of less frequently targeted ports revealed a number of interesting leads, including activity on ports associated with Redis (6379), PostgreSQL (5432), and Apache Solr (8983). The activity on port 8983 was selected for further investigation due to the known history of critical vulnerabilities in Apache Solr.

### 3.3 Analysis of Apache Solr Reconnaissance

A deeper analysis of the activity on port 8983 revealed a targeted reconnaissance campaign with the following characteristics:

*   **Source IPs:**
    *   `142.93.0.16` (DigitalOcean)
    *   `68.183.119.17` (DigitalOcean)
*   **User-Agent:** `Go-http-client/1.1`
*   **Targeted URLs:**
    *   `/solr/admin/cores?action=STATUS&wt=json`
    *   `/solr/admin/info/system`
    *   `/`

The use of the `Go-http-client/1.1` user-agent suggests that the attack was carried out by an automated tool written in the Go programming language. The targeted URLs are used to enumerate the Solr instance and gather information about its configuration, including the version of Solr, the operating system, and the Java version. This is a common first step for an attacker looking to exploit a known vulnerability.

### 3.4 CVE Correlation

An analysis of the CVEs detected by the honeypot during the investigation window did not reveal any that were directly related to Apache Solr. This does not mean that the attacker was not attempting to exploit a CVE; it simply means that the honeypot did not generate an alert with a CVE tag for this specific activity. It is common for attackers to first probe for the existence of a service and then to launch a separate attack to exploit a vulnerability.

## 4.0 Conclusion

The investigation successfully identified a low-volume, high-interest attack vector targeting Apache Solr. This attack is notable because it is not a "spray and pray" attack, but rather a targeted reconnaissance campaign against a specific service. The attacker's TTPs suggest the use of an automated tool to identify and enumerate Solr instances, with the likely goal of exploiting a known vulnerability.

This type of attack is often a precursor to a more serious compromise, and it highlights the importance of looking beyond the high-volume attacks to identify more subtle and potentially more dangerous threats.

**Recommendations:**

*   Organizations running Apache Solr should ensure that their instances are patched and up to date, and that access to the Solr admin interface is restricted to authorized users.
*   Security teams should monitor for the TTPs identified in this report, including the use of the `Go-http-client/1.1` user-agent and requests to the Solr admin URLs.

This investigation demonstrates the value of looking for "minutia attacks" in honeypot data. By filtering out the noise of high-volume attacks, it is possible to identify and analyze more targeted and potentially more dangerous threats.
