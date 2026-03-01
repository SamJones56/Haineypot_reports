# Security Investigation Report - Last 60 Minutes

**Timeframe**: 2026-03-01T11:00:10Z to 2026-03-01T12:00:10Z (Baseline) / 2026-03-01T11:00:34Z to 2026-03-01T12:00:34Z (KnownSignal)

## Overview

This report summarizes the findings of a security investigation covering the last 60 minutes. A total of **16,588 attacks** were observed. The top attacking countries were India (7,247), United States (3,282), and Germany (1,323). The most active attacker source IPs included `64.227.173.38` (4,080 attacks) and `203.223.190.168` (3,147 attacks). Top attack signatures included "SURICATA IPv4 truncated packet" (3,957) and "SURICATA AF-PACKET truncated packet" (3,957). "Generic Protocol Command Decode" was the most frequent alert category (8,415).

## Detailed Findings

### 1. Adbhoney Botnet Activity (IP: 118.39.60.141)

*   **Candidate ID**: `ip_investigation-118.39.60.141`
*   **Classification**: Known Exploit Campaign (Botnet)
*   **Confidence**: High
*   **Observed Evidence**:
    *   **Source IP**: `118.39.60.141` (South Korea, ASN 4766 - Korea Telecom)
    *   **Event Count**: 28 events from this IP
    *   **First Seen**: 2026-03-01T11:20:18Z
    *   **Last Seen**: 2026-03-01T11:31:58Z
    *   **Commands Observed**: Execution of `/data/local/tmp/nohup /data/local/tmp/trinity`, `am start -n com.ufo.miner/com.example.test.MainActivity`, `chmod 0755 /data/local/tmp/nohup`, `pm path com.ufo.miner`, `ps | grep trinity`, `rm -rf /data/local/tmp/*`.
    *   **Malware Hashes Correlated (Adbhoney)**:
        *   `dl/26e72314a3c85dcd726ce1119d35279cb252d296cbe95504addd948ad32da9cc.raw`
        *   `dl/7a656791b445fff02ac6e9dd1081cc265db935476a9ee71139cb6aef52102e2b.raw`
        *   `dl/d7188b8c575367e10ea8b36ec7cca067ef6ce6d26ffa8c74b3faa0b14ebb8ff0.raw`
    *   **Service Fingerprint**: Dest Port 5555, Protocol TCP, Application Hint: Android Debug Bridge (ADB)
*   **OSINT Correlation**: Public reporting confirms that the "trinity" payload and "com.ufo.miner" package are associated with the **ADB.Miner / Trinity botnet**, an established cryptomining campaign active since 2018, targeting exposed Android Debug Bridge interfaces.
*   **Evidence Gaps**: Raw event logs could not be retrieved due to tool failure, preventing inspection of downloader commands for potential staging URLs.
*   **Novelty Score**: 1 (Known activity)
*   **Infrastructure Value Score**: 3 (Self-contained compromised host, no further leads)
*   **Campaign Shape**: Unknown (limited to single IP)

### 2. PHPUnit Vulnerability Scanning (IP: 83.168.68.72)

*   **Candidate ID**: `ip_investigation-83.168.68.72`
*   **Classification**: Known Exploit Campaign (Vulnerability Scan)
*   **Confidence**: High
*   **Observed Evidence**:
    *   **Source IP**: `83.168.68.72` (Poland, ASN 202520 - SkyPass Solutions Sp. z.o.o.)
    *   **Event Count**: 174 events from this IP
    *   **First Seen**: 2026-03-01T11:11:21Z
    *   **Last Seen**: 2026-03-01T11:14:03Z (brief 3-minute window)
    *   **Targeted Port/Protocol**: HTTP port 80
    *   **Web Paths Observed**:
        *   `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
        *   `/admin/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
        *   `/api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
        *   `/app/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
        *   `/apps/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
        *   Other paths indicating a broad scanning campaign, including PHP LFI/RCE (`allow_url_include`), path traversal (`cgi-bin`), ThinkPHP RCE, and PEAR command injection.
    *   **User Agent**: `libredtail-http` (consistent across all requests)
*   **OSINT Correlation**: The paths targeting `eval-stdin.php` are characteristic of scanning for **CVE-2017-9841**, a critical Remote Code Execution (RCE) vulnerability in older versions of the PHPUnit framework, listed in CISA's Known Exploited Vulnerabilities Catalog.
*   **Campaign Shape**: Spray (multiple exploit attempts)
*   **Novelty Score**: 1 (Known vulnerability scanning)
*   **Infrastructure Value Score**: Not explicitly calculated, but scanner IP with multiple exploit attempts.

## Other Observations

### High Volume SURICATA Alerts

*   **Signatures**: "SURICATA IPv4 truncated packet" (3,957 counts) and "SURICATA AF-PACKET truncated packet" (3,957 counts).
*   **Category**: Generic Protocol Command Decode (8,415 counts).
*   **Investigation Status**: Attempts to correlate these alerts with specific source IPs or destination ports failed due to data retrieval limitations. Raw event samples provided limited metadata, preventing further analysis. This lead was a dead end.

### Conpot Protocol Activity

*   **Protocol Observed**: `guardian_ast` (2 counts)
*   **Investigation Status**: Initial attempts to query for Conpot events with this protocol returned no data, indicating a possible issue with the query or data availability for that specific timeframe and filter. This lead was a dead end.

### Credential Noise

*   **Top Usernames**: `oracle` (183), `root` (170), `mysql` (156), `admin` (89), `test` (64).
*   **Top Passwords**: `123456` (202), `123` (64), `12345678` (62), `1234` (58), `password` (47).
*   **OS Distribution (P0f)**: Primarily `Windows NT kernel` (19,316) and `Linux 2.2.x-3.x` (8,724).
*   **Assessment**: These appear to be standard background noise from brute-force attempts and common credential spraying, not directly correlated with the identified campaigns.

### Reported CVEs

*   `CVE-2024-14007`, `CVE-2002-0013`, `CVE-2024-4577`, `CVE-2021-41773`.
*   **Assessment**: While `CVE-2024-4577` was initially considered in relation to the PHPUnit probing, it was determined to be a distinct vulnerability (PHP-CGI on Windows) from `CVE-2017-9841` (PHPUnit `eval-stdin.php`). No direct correlations were established for the other CVEs with the identified activities in this timeframe.

## Conclusion

The investigation identified two distinct known exploit campaigns:

1.  **ADB.Miner / Trinity Botnet Activity**: A single source IP (`118.39.60.141`) from South Korea was observed attempting to deploy the "trinity" cryptominer on Android Debug Bridge (ADB) interfaces (port 5555). This is a known, established botnet campaign.
2.  **PHPUnit RCE (CVE-2017-9841) Scanning**: A source IP (`83.168.68.72`) from Poland conducted a brief, widespread scan for various web vulnerabilities, including the PHPUnit RCE (CVE-2017-9841) via `eval-stdin.php` paths, using the user agent `libredtail-http`. This is typical scanner behavior for an established CVE.

Other high-volume alerts and minor observations were primarily background noise or could not be fully investigated due to data limitations or lack of pivotable indicators.

**Recommendations**:

*   Ensure all internet-exposed Android Debug Bridge (ADB) interfaces are properly secured or disabled if not required.
*   Patch or remove outdated PHPUnit installations from production environments and ensure the `/vendor` directory is not publicly accessible.
*   Monitor for connections from `118.39.60.141` and `83.168.68.72` and block if appropriate.
*   Further investigation into the `SURICATA IPv4 truncated packet` and `SURICATA AF-PACKET truncated packet` alerts might require access to more detailed packet metadata to identify underlying causes.