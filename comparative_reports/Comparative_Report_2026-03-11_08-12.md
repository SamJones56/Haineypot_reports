# Comparative Threat Hunting Report: 2026-03-11T08:00:05Z to 2026-03-11T12:00:05Z

## 1. Executive Summary of Comparison

This comparative analysis examines the threat hunting reports and corresponding agent logs generated for the period of 2026-03-11T08:00:05Z to 2026-03-11T12:00:05Z. Both the "Deep Agent" and "Default Agent" identified a common set of major threats, including a high-volume VNC scanning campaign and exploitation attempts against web vulnerabilities. A critical consistency across both reports is the acknowledgment of a backend tool failure that prevented the full analysis of Industrial Control System (ICS) honeypot activity.

The Deep Agent's report provides a more detailed breakdown of the web exploitation, explicitly identifying the "RedTail Cryptominer" scanner and linking multiple web exploit attempts to specific CVEs (PHPUnit RCE, ThinkPHP RCE, LFI via `pearcmd`). The Default Agent, while identifying similar activities (e.g., PHP RCE via soft hyphen, PHPUnit RCE scanning), presents them with less specific attribution to a named scanner or as distinct novel candidates that were later reclassified.

### Key Similarities:
- **Time Window**: Both reports cover the same time frame: 2026-03-11T08:00:04Z to 2026-03-11T12:00:04Z.
- **Degraded Mode**: Both reports indicate a `degraded_mode` set to `true` due to a backend tool failure related to ICS honeypot data.
- **Top Services/Ports of Interest**: VNC (5900), HTTP (80), and ICS protocols (`guardian_ast`, `kamstrup_management_protocol`, `IEC104`) are consistently highlighted.
- **VNC Exploitation (CVE-2006-2369)**: Both reports identify a high-volume VNC scanning campaign mapped to CVE-2006-2369, originating from `185.231.33.22` (AS211720 / Datashield, Inc.). This is consistently classified as commodity/botnet activity.
- **ICS Protocol Probes**: Both agents detected probes against ICS protocols, and both noted the inability to attribute source IPs due to tool failures. The "guardian_ast" protocol is mentioned in both as an unusual finding.
- **Credential Noise**: Standard SSH brute-force attempts with common usernames/passwords are noted by both.
- **Android ADB Reconnaissance**: Both reports mention reconnaissance commands executed on Adbhoney from `45.135.194.48`.
- **PHPUnit RCE Scanning**: Both reports acknowledge low-volume probes for PHPUnit RCE vulnerability via `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`.

### Key Differences:
- **Web Exploitation Details & Attribution**:
    - **Deep Agent**: Identifies the "RedTail Cryptominer" scanner (`libredtail-http` user-agent) explicitly. It lists specific web vulnerabilities tested by this scanner: PHPUnit (CVE-2017-9841), ThinkPHP RCE (CVE-2018-20062 / CVE-2019-9082), and LFI via `pearcmd`. Initially classified as a novel candidate (NOV-01), it was reclassified as emerging N-day after OSINT.
    - **Default Agent**: Identifies exploitation of CVE-2024-4577 (PHP RCE) using a "soft hyphen" argument injection. This activity was initially a "novel_exploit_candidate" (NOV-01) and later mapped to CVE-2024-4577 via OSINT. It also lists two other "Emerging n-day Exploitation" candidates: CVE-2025-55182 (React2Shell) and CVE-2024-14007 (Shenzhen TVT NVR), which are not explicitly mentioned in the Deep Agent's report.
- **Number of Candidates/Findings**:
    - **Deep Agent**: Focuses on 1 "Emerging n-day" (RedTail Scanner/NOV-01 reclassification), 3 "Botnet/Campaigns" (VNC, RedTail, Android, .env), and 1 "Odd Service".
    - **Default Agent**: Identifies 3 "Emerging n-day" (React2Shell, Shenzhen TVT NVR, PHP RCE/NOV-01 reclassification), 1 "Botnet/Campaign" (VNC), 1 "Novel Exploit Candidate" (which was reclassified), 1 "Odd Service", and 1 "Suspicious Unmapped Monitor" (Android ADB).
- **Material Gaps/Evidence Gaps**: Both agree on the ICS data correlation failure, but phrase the impact slightly differently.
    - **Deep Agent**: "The failure of the `two_level_terms_aggregated` tool for `Conpot` data prevented the promotion of ICS-related activity into a full candidate with source attribution."
    - **Default Agent**: "Discovery was materially affected by query failures (`two_level_terms_aggregated`, `kibanna_discover_query`) against Conpot data, which prevented the correlation of source IPs to the observed ICS protocol interactions."
- **Audit Trail Detail**: Both reports include an audit trail of agent actions. The Deep Agent's audit trail lists the `SaveReportAgent` and its actions as part of the report generation, which is meta-reporting on its own actions. The Default Agent's report also includes this.

## 2. Detailed Comparative Analysis

### 2.1 Investigation Scope
Both reports define the same investigation period. The `degraded_mode` status is consistent, indicating the shared tool failure impacting ICS data.

### 2.2 Executive Triage Summary
The core "Top Services/Ports of Interest" and "Top Confirmed Known Exploitation" are largely consistent regarding VNC. However, the Deep Agent's "Top Unmapped Exploit-like Items" is directly mapped to the "RedTail Cryptominer" scanner, detailing its multi-exploit nature. The Default Agent, in contrast, lists "CVE-2025-55182 (React2Shell)" and "CVE-2024-4577 (PHP RCE)" as "Top Confirmed Known Exploitation" which were not explicitly in the Deep Agent's top findings, though the PHP RCE is the reclassified NOV-01 in Default. This suggests potential differences in how initial "unmapped" items are categorized or reported at the executive summary level.

### 2.3 Candidate Discovery Summary
Both agents analyzed 36,961 total attacks. The Deep Agent identified 1 novel candidate (reclassified as N-day), 3 botnet/campaigns, and 1 odd service. The Default Agent reported 6 initial candidates (emerging n-days, botnet, novel, odd-service, suspicious monitoring). This indicates the Default Agent might have a broader or slightly different initial discovery strategy, or simply a different way of counting/categorizing initial candidates. Both agree on the material gap concerning Conpot data.

### 2.4 Emerging n-day Exploitation
This section highlights the most significant divergence.
- **Deep Agent**: Identifies NOV-01 (PHPUnit RCE, ThinkPHP RCE, LFI via `pearcmd`) as reclassified emerging n-day. It attributes this to the "RedTail Cryptominer" scanner with a `libredtail-http` user-agent.
- **Default Agent**: Identifies three distinct emerging n-day exploits:
    - NDE-01: CVE-2025-55182 (React2Shell) on port 9000.
    - NDE-02: CVE-2024-14007 (Shenzhen TVT NVR) on port 6036.
    - NOV-01 (Re-classified): CVE-2024-4577 (PHP RCE) on port 80, using the soft hyphen argument injection.
The Deep Agent's NOV-01 encapsulates a set of web exploits attributed to a specific tool, while the Default Agent's NOV-01 is a single PHP RCE, and it introduces two completely new, high-severity CVEs (React2Shell, Shenzhen TVT NVR) that were not present in the Deep Agent's report. This suggests that the Default Agent either identified more diverse N-day exploitation or categorized existing observations differently.

### 2.5 Novel or Zero-Day Exploit Candidates
Both reports conclude no candidates remained truly novel after OSINT validation, with any initial novel findings being reclassified as emerging N-day.

### 2.6 Botnet/Campaign Infrastructure Mapping
- **Deep Agent**: Maps three distinct campaigns: RedTail Scanner (from NOV-01), VNC Scanner (BOT-01), and .env Scanner (BOT-03), and Android Fingerprinting (BOT-02).
- **Default Agent**: Only explicitly maps one botnet campaign: BOT-01 (VNC Auth Bypass Campaign). The other campaigns identified by the Deep Agent (RedTail, .env scanner, Android fingerprinting) are either merged into "Emerging n-day" (RedTail/CVE-2024-4577) or "Known-Exploit / Commodity Exclusions" (PHP RCE Scanning for CVE-2017-9841, Common Web Scanning for /.env, ADB Reconnaissance) or "Suspicious Unmapped Monitor" (ADB Reconnaissance). This shows a significant difference in how campaigns are segmented and reported.

### 2.7 Odd-Service / Minutia Attacks
Both reports identify "ODD-01: Probing of ICS Protocols" with identical evidence summaries and confidence (low/provisional) due to the tool failure. The Deep Agent mentions `guardian_ast`, `kamstrup_management_protocol`, and `IEC104`, while the Default Agent also lists these and provides more context about `guardian_ast` likely being a custom or mislabeled protocol based on OSINT.

### 2.8 Known-Exploit / Commodity Exclusions
This section also shows differences due to varying classifications earlier in the workflow.
- **Deep Agent**: Excludes VNC Exploitation (CVE-2006-2369) (which is also a botnet) and Credential Noise.
- **Default Agent**: Excludes VNC Auth Bypass (CVE-2006-2369) (also a botnet), SSH Credential Stuffing, PHP RCE Scanning (CVE-2017-9841), Common Web Scanning (`.env`), and ADB Reconnaissance. The Default Agent's exclusions list is more comprehensive, likely because it does not promote some of these to separate "botnet/campaign" or "novel candidate" categories, but rather categorizes them as commodity.

### 2.9 Infrastructure & Behavioral Classification
Both reports classify behavior. The Deep Agent's classification directly reflects its identified campaigns (RedTail as Exploitation Scanning, VNC as Spray Exploitation Scanning, Android and .env as Reconnaissance, ICS as Odd-Service Reconnaissance). The Default Agent provides a more general overview of exploitation vs. scanning, campaign shapes (fan-in for VNC), and odd-service fingerprints, but without the granular detail on specific scanner names like "RedTail".

### 2.10 Evidence Appendix
Both reports provide evidence for their key findings. The Deep Agent focuses on RedTail Scanner and VNC Scanner. The Default Agent provides evidence for CVE-2025-55182, CVE-2006-2369 (VNC), and CVE-2024-4577 (PHP RCE). This again highlights the different focus and categorization of findings between the two agents.

### 2.11 Indicators of Interest
Both provide lists of IPs, User-Agents (Deep Agent), Paths/Payloads, and CVEs. The Deep Agent's list includes the `libredtail-http` user-agent and specific exploit paths related to PHPUnit, ThinkPHP, and `pearcmd`. The Default Agent's list of IPs and CVEs is more diverse, reflecting its broader range of identified N-day exploits (React2Shell, Shenzhen TVT NVR, PHP RCE).

### 2.12 Backend Tool Issues
Both reports identify the `two_level_terms_aggregated` tool failure for Conpot data. The Default Agent additionally mentions `kibanna_discover_query` as a failed tool. Both agree on the impact of this failure on ICS activity attribution.

### 2.13 Agent Action Summary (Audit Trail)
Both reports offer detailed audit trails, outlining the purpose, inputs, actions, and key results of each agent in their respective workflows. They both acknowledge their own role in generating the report and saving it. The main difference here is the specific set of `actions_taken` and `key_results` due to their different internal processing and classification decisions. The Default Agent's audit trail for `CandidateDiscoveryAgent` indicates it queried for IPs related to top CVEs, aggregated data by path and protocol, and searched for specific exploit artifacts, which aligns with its broader set of N-day findings. The Deep Agent's `CandidateDiscoveryAgent` also aggregated data using `two_level_terms_aggregated` and enriched with `search`, leading to its specific candidate set.

## 3. Conclusion

Both the Deep Agent and Default Agent effectively analyzed the provided data, identifying critical security events and highlighting the persistent issue with ICS data correlation. However, their approaches to classifying and reporting web-based exploitation differ significantly. The Deep Agent excelled in attributing a multi-exploit web scanning campaign to a specific, known threat actor/tool ("RedTail Cryptominer"), providing a cohesive picture of that activity. The Default Agent, while also identifying a PHP RCE (initially novel), additionally discovered and reported on two other high-severity N-day exploits (React2Shell, Shenzhen TVT NVR) not explicitly found or highlighted by the Deep Agent.

The differences in reporting emphasize that while both agents perform a comprehensive analysis, their internal logic and prioritization lead to varied interpretations and categorizations of the same underlying event data. For future threat hunting, it would be beneficial to either align the web exploitation categorization for consistency or leverage both reports to gain a more complete and diverse understanding of the threat landscape, especially regarding different N-day vulnerabilities being exploited. The consistent identification of the ICS data pipeline failure is a critical operational insight that requires immediate attention to enhance future investigations.
