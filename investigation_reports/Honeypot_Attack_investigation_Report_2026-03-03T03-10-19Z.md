## Investigation Report: Last 60 Minutes (2026-03-03T02:00:10Z - 2026-03-03T03:00:10Z)

### Executive Summary

This report summarizes network attack activity observed in the last 60 minutes. A total of 4402 attacks were recorded. The top attacking countries are the United States, India, Germany, Romania, and Australia. DigitalOcean, LLC (ASN 14061) is the leading Autonomous System (AS) of origin for observed attacks, accounting for a significant portion of traffic.

Key findings include widespread scanning and exploitation attempts targeting various services, including:

*   **VNC servers:** High volume scanning on VNC-related ports (5900-5926) from various sources, indicating brute-force or vulnerability scanning.
*   **SSH services:** Scanning on standard and unusual SSH ports, with detections of "SSH-2.0-Go version string" and "SSH session in progress on Unusual Port."
*   **Industrial Control Systems (ICS):** Interactions with a Conpot honeypot using the "guardian_ast" protocol and a specific "I20100 Inventory" command, indicating reconnaissance against ICS systems.
*   **Redis instances:** Unusual HTTP-like probing ("GET / HTTP/1.0") and "info" commands on a Redis honeypot, suggesting reconnaissance or misconfiguration exploitation attempts.
*   **Web application reconnaissance:** Targeted requests for sensitive paths like "/backup/" and "/manage/account/login" on a Tanner honeypot.
*   **Coordinated Campaigns against Specific Services:** Multiple source IPs are engaged in spray campaigns targeting:
    *   **Port 50050:** Exhibiting mixed HTTP and SMB traffic, including a known Nmap probe for "Trinity.txt.bak."
    *   **MikroTik RouterOS API (port 8728):** Indicating reconnaissance and potential brute-force attempts.
    *   **Elasticsearch (port 9200):** Targeting unauthenticated access and potential RCE vulnerabilities.
    *   **Docker Daemon (port 2375):** Exposed without TLS, a critical misconfiguration offering root access.
    *   **MongoDB (port 27019):** Highly concerning due to the active exploitation of CVE-2025-14847 (MongoBleed).

Credential stuffing attempts with common usernames (mysql, oracle, ubuntu) and weak passwords (123456, password) remain prevalent.

### Baseline Attack Overview

*   **Total Attacks:** 4402
*   **Top Attacking Countries:**
    *   United States: 2226
    *   India: 446
    *   Germany: 383
    *   Romania: 363
    *   Australia: 200
*   **Top Attacker Source IPs:**
    *   206.189.193.104 (538 attacks)
    *   64.227.163.66 (435 attacks)
    *   64.226.116.132 (308 attacks)
    *   129.212.179.18 (261 attacks)
    *   129.212.188.196 (260 attacks)
*   **Top Attacker ASNs:**
    *   DigitalOcean, LLC (ASN 14061): 2443 attacks
    *   Unmanaged Ltd (ASN 47890): 391 attacks
    *   Private Layer INC (ASN 51852): 201 attacks
    *   Google LLC (ASN 396982): 137 attacks
    *   Akamai Connected Cloud (ASN 63949): 104 attacks
*   **Country to Port Activity:**
    *   **United States:** Primarily targeting ports 5925, 5926 (VNC), and 50050.
    *   **India:** Primarily targeting port 22 (SSH).
    *   **Germany:** Primarily targeting port 22 (SSH), 4000, and 8728 (MikroTik API).
    *   **Romania:** Primarily targeting port 22 (SSH), 25, and 8111.
    *   **Australia:** Primarily targeting ports 5906, 5907, and 5911 (VNC).

### Known Signals and Emerging Exploitation

*   **Top Alert Signatures:**
    *   GPL INFO VNC server response (2217) - *High volume VNC scanning/brute force.*
    *   SURICATA IPv4 truncated packet (175) / SURICATA AF-PACKET truncated packet (175) - *Generic packet integrity alerts.*
    *   ET DROP Dshield Block Listed Source group 1 (128) - *General blocking of known bad IPs.*
    *   ET INFO SSH-2.0-Go version string Observed in Network Traffic (115) - *SSH scanning.*
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port (68) - *Scanning for RDP on unusual ports.*
    *   ET INFO SSH session in progress on Unusual Port (24) - *SSH evasion/C2 reconnaissance.*
    *   ET SCAN NMAP -sS window 1024 (45) - *Nmap scanning.*
*   **Top Alert Categories:**
    *   Misc activity (2428)
    *   Generic Protocol Command Decode (497)
    *   Misc Attack (387)
    *   Attempted Information Leak (140)
*   **CVEs Observed:**
    *   CVE-2019-11500 (3)
    *   CVE-2021-3449 (3)
    *   CVE-2024-14007 (2)
    *   CVE-2002-0013 CVE-2002-0012 (1)

### Credential Noise

High volume brute force attempts were observed targeting common usernames like 'mysql', 'oracle', 'ubuntu', and 'postgres' using weak passwords such as '123456', '12345678', and 'password'.

### Honeypot Specific Activity

*   **Conpot Honeypot:** 5 interactions observed using the 'guardian\_ast' protocol with the input `b'\x01I20100'`. This is identified as the "I20100 Inventory" command for Gilbarco Veeder-Root Guardian AST systems, indicating ICS/SCADA reconnaissance.
*   **Redis Honeypot:** 1 "GET / HTTP/1.0" command and 1 "info" command recorded. "GET / HTTP/1.0" is not a native Redis command, suggesting HTTP-like probing or misconfiguration exploitation attempts. The "info" command is legitimate but its context alongside HTTP-like requests points to probing.
*   **Tanner Honeypot:** 12 requests observed, including targeted reconnaissance for sensitive paths:
    *   `/backup/` (2 requests from 204.76.203.18) - Seeking exposed backup files.
    *   `/manage/account/login` (1 request from 216.180.246.83) - Targeting administrative login portals for potential brute-force or credential stuffing.

### Botnet Campaign Mapping

| Item ID | Seed Reason | Campaign Shape | Infrastructure Indicators (Source IPs) | Observed Evidence | Infrastructure Value Score | Confidence | Provisional | Required Followup |
| :------ | :---------- | :------------- | :----------------------------------- | :---------------- | :------------------------- | :--------- | :---------- | :---------------- |
| BCM-001 | Coordinated scanning/exploitation on unusual port 50050. | spray | 157.230.217.238, 170.187.158.219, 45.33.60.102 | 117 total hits on dest\_port 50050, 39 hits from each IP. Includes HTTP OPTIONS, GET (`/nice%20ports%2C/Tri%6Eity.txt%2ebak`), and SMB events. The `Trinity.txt.bak` URI is a known Nmap artifact. | 3 | High | False | Continue monitoring for payloads beyond Nmap probing. |
| BCM-002 | Coordinated scanning/exploitation on MikroTik RouterOS API port 8728. | spray | 45.205.1.5, 185.169.4.141, 45.205.1.110, 64.226.91.27, 84.32.191.60 | 124 total hits on dest\_port 8728. | 3 | High | False | Investigate payload/context of port 8728 traffic. |
| BCM-003 | Coordinated scanning/exploitation on Elasticsearch port 9200. | spray | 118.194.248.4, 66.132.153.138, 66.132.153.129, 134.122.176.63, 205.210.31.250 | 40 total hits on dest\_port 9200. | 3 | High | False | Investigate payload/context of port 9200 traffic. |
| BCM-004 | Coordinated scanning/exploitation on Docker daemon port 2375 (without TLS). | spray | 185.242.226.46, 157.173.122.74, 47.253.183.81, 47.96.228.248 | 36 total hits on dest\_port 2375. | 3 | High | False | Investigate payload/context of port 2375 traffic. |
| BCM-005 | Coordinated scanning/exploitation on MongoDB port 27019. | spray | 137.184.195.171, 198.199.120.221, 68.183.26.186, 157.230.189.8 | 35 total hits on dest\_port 27019. | 3 | High | False | Investigate payload/context of port 27019 traffic; high priority due to CVE-2025-14847 (MongoBleed). |
| BCM-006 | SSH activity detected on unusual ports, indicating potential campaign activity. | spray | Unknown (specific IPs/ports not extractable by tool) | 24 events with Suricata alert 'ET INFO SSH session in progress on Unusual Port'. | 1 | High | False | Delineate specific IPs/ports if possible with other tools/methods. |

### Odd Service Minutia Attacks

| Item ID | Seed Reason | Service Fingerprint | Infrastructure Indicators (Source IPs) | Campaign Shape | Observed Evidence | Knownness Checks Performed | Novelty Score | Confidence | Provisional | Required Followup |
| :------ | :---------- | :------------------ | :----------------------------------- | :------------- | :---------------- | :----------------------- | :------------ | :--------- | :---------- | :---------------- |
| OSMA-001 | Conpot honeypot interaction with Guardian AST ICS protocol and specific input. | Conpot honeypot, 'guardian_ast' protocol, input: 'b'\x01I20100'' | Unknown (not extractable by tool) | Unknown | 5 interactions with Conpot, showing 'guardian_ast' protocol and input 'b'\x01I20100''. | OSINT confirms this as a standard Guardian AST 'I20100 Inventory' command. | 1 | High | False | Investigate source IPs and context of these ICS probes. |

### Suspicious Unmapped Monitor

| Item ID | Seed Reason | Service Fingerprint | Infrastructure Indicators (Source IPs) | Campaign Shape | Observed Evidence | Knownness Checks Performed | Novelty Score | Confidence | Provisional | Required Followup |
| :------ | :---------- | :------------------ | :----------------------------------- | :------------- | :---------------- | :----------------------- | :------------ | :--------- | :---------- | :---------------- |
| SUM-001 | Tanner honeypot requests for sensitive paths indicating targeted reconnaissance. | HTTP on Tanner honeypot. | 204.76.203.18 (for /backup/), 216.180.246.83 (for /manage/account/login and /) | Targeted reconnaissance from individual IPs | 2 hits on '/backup/' from 204.76.203.18, 1 hit on '/manage/account/login' from 216.180.246.83. | OSINT confirms these are classic web reconnaissance patterns. | 1 | High | False | Monitor these IPs for further activity, analyze full requests if possible. |
| SUM-002 | Unusual HTTP-like requests ('GET / HTTP/1.0') and 'info' command on Redis honeypot. | Redis honeypot, commands: 'GET / HTTP/1.0', 'info'. | Unknown (not extractable by tool) | Unknown | 1 event for 'GET / HTTP/1.0', 1 event for 'info' command on Redis. | OSINT confirms 'GET / HTTP/1.0' is not native to Redis and indicates probing. | 1 | High | False | Investigate source IPs for these Redis interactions if possible. |

### Evidence Gaps and Failed Queries

*   **Evidence Gaps:**
    *   Unable to reliably retrieve raw event details (including source IPs and full payloads) for Conpot and Redis interactions using general Kibana-style discover queries due to tool limitations ('Expected text but found START\_ARRAY' errors).
    *   Unable to extract specific source IPs and destination ports for 'ET INFO SSH session in progress on Unusual Port' from `suricata_lenient_phrase_search` due to empty 'hits' array in tool output, preventing detailed infrastructure mapping.
*   **Failed Queries:**
    *   `kibanna_discover_query` (term=conpot.input.keyword, value=b'\\x01I20100')
    *   `kibanna_discover_query` (term=type.keyword, value=Conpot)
    *   `two_level_terms_aggregated` (primary_field=conpot.input.keyword, secondary_field=src_ip.keyword, type_filter=Conpot)
    *   `two_level_terms_aggregated` (primary_field=conpot.protocol.keyword, secondary_field=src_ip.keyword)
    *   `kibanna_discover_query` (term=redis.command.keyword, value=GET / HTTP/1.0)
    *   `kibanna_discover_query` (term=redis.command.keyword, value=info)
    *   `two_level_terms_aggregated` (primary_field=type.keyword, secondary_field=src_ip.keyword, type_filter=Redis)

### Recommendations for Follow-up

1.  **Prioritize Investigation of MongoDB (Port 27019) and Docker (Port 2375) Activity:** Given the high severity of CVE-2025-14847 (MongoBleed) and the root-level access granted by an unsecured Docker daemon, deeper investigation into the specific payloads and impact of these attacks is critical.
2.  **Investigate Unusual Port 50050 Activity:** While some activity includes a known Nmap probe, the mix of HTTP and SMB traffic warrants further inspection to understand the full scope and intent beyond reconnaissance.
3.  **Enhance Honeypot Telemetry:** Address the evidence gaps related to Conpot and Redis by improving honeypot logging and data extraction capabilities to capture full payloads and source IPs.
4.  **Delineate SSH on Unusual Ports:** Implement advanced logging or use alternative tools to identify the specific source IPs and destination ports associated with 'ET INFO SSH session in progress on Unusual Port' alerts to determine if it's legitimate or malicious C2 activity.
5.  **Monitor Identified IPs:** Continuously monitor the source IPs identified in the botnet campaigns and suspicious reconnaissance activities for further malicious behavior.
6.  **OSINT on Identified Payloads:** Conduct further OSINT on any unique payloads or command strings observed in the future for any of these activities to identify known attack tools or campaigns.
