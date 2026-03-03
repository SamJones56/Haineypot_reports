{
  "report_id": "thr-20260301102237-7f9a1",
  "investigation_start": "2026-03-01T09:22:37Z",
  "investigation_end": "2026-03-01T10:22:37Z",
  "executive_summary": {
    "tldr": "A high volume of automated attacks was observed, dominated by a widespread campaign leveraging the DoublePulsar backdoor against SMB (TCP/445). Additionally, targeted exploitation attempts were detected for a recent vulnerability, CVE-2024-14007 (Shenzhen TVT NVMS-9000 auth bypass). Reconnaissance against ICS/SCADA systems was also noted via the 'guardian_ast' protocol on the Conpot honeypot. All high-interest activities were successfully mapped to known, publicly documented threats, reducing their novelty but confirming their active status in the wild. The investigation was partially hindered by tool errors preventing deep dives on some keyword-based artifacts.",
    "key_threats_identified": [
      {
        "threat_type": "Known Exploit Campaign",
        "details": "Widespread DoublePulsar backdoor installation attempts targeting SMB (TCP/445), consistent with established botnet activity.",
        "osint_link": "Established (related to EternalBlue/WannaCry)."
      },
      {
        "threat_type": "N-day Exploit",
        "details": "Targeted scanning and exploitation of CVE-2024-14007, a recent authentication bypass in Shenzhen TVT NVMS-9000 firmware.",
        "osint_link": "Recently disclosed (2024), public exploit info available."
      },
      {
        "threat_type": "ICS/SCADA Reconnaissance",
        "details": "Interaction with the Conpot honeypot emulating the 'guardian_ast' protocol, which mimics a Veeder-Root device with known authentication weaknesses.",
        "osint_link": "Established vulnerability pattern in ICS environments."
      }
    ],
    "commodity_noise_summary": "Standard background noise included widespread scanning for SSH (port 22) and VNC (ports 5925, 5926), and HTTP-based scanning for sensitive '.env' configuration files. This activity is considered commodity and was excluded from deep investigation."
  },
  "overall_activity_baseline": {
    "total_events": 16762,
    "top_source_countries": [
      {
        "country": "India",
        "count": 4115
      },
      {
        "country": "United States",
        "count": 3168
      },
      {
        "country": "Venezuela",
        "count": 3148
      },
      {
        "country": "Vietnam",
        "count": 2550
      }
    ],
    "top_source_asns": [
      {
        "asn": 14061,
        "organization": "DigitalOcean, LLC",
        "count": 7456
      },
      {
        "asn": 263703,
        "organization": "VIGINET C.A",
        "count": 3147
      },
      {
        "asn": 18403,
        "organization": "FPT Telecom Company",
        "count": 2462
      }
    ]
  },
  "validated_threat_details": [
    {
      "candidate_id": "exploit-DP-SMB-1",
      "classification": "Known Exploit Campaign",
      "threat_description": "A high-volume, automated campaign distributing the DoublePulsar backdoor.",
      "telemetry_summary": {
        "finding": "1,862 alerts for 'ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication' were observed, strongly correlated with 6,592 events targeting TCP port 445 (SMB).",
        "indicators": [
          "signature_id: 2024766",
          "dest_port: 445",
          "proto: TCP"
        ],
        "top_source_asns": [
          "DigitalOcean, LLC (AS14061)",
          "VIGINET C.A (AS263703)",
          "FPT Telecom Company (AS18403)"
        ]
      },
      "osint_validation": {
        "public_mapping_found": true,
        "mapped_to": "campaign",
        "mapping_name": "DoublePulsar (related to EternalBlue/WannaCry campaigns)",
        "recency": "established",
        "novelty_impact": "reduces_novelty",
        "confidence": "High",
        "notes": "OSINT confirms the Suricata signature corresponds to the well-known DoublePulsar backdoor, frequently delivered via the EternalBlue exploit against SMBv1. This is established, widespread attack behavior."
      }
    },
    {
      "candidate_id": "exploit-CVE-2024-14007-1",
      "classification": "N-Day Exploit",
      "threat_description": "Targeted exploitation attempts against a recent vulnerability in Shenzhen TVT NVMS-9000 devices.",
      "telemetry_summary": {
        "finding": "Two alerts for 'ET WEB_SPECIFIC_APPS Shenzhen TVT NVMS-9000 Information Disclosure Attempt (CVE-2024-14007)' were observed.",
        "indicators": [
          "cve: CVE-2024-14007",
          "dest_ports: [17000, 17001]",
          "source_ips: ['46.151.178.13', '89.42.231.179']"
        ],
        "deep_dive_notes": "The source IP 46.151.178.13 (AS211443, Sino Worldwide Trading Limited) was also observed making an HTTP request with a suspicious User-Agent 'Hello World'."
      },
      "osint_validation": {
        "public_mapping_found": true,
        "mapped_to": "CVE",
        "mapping_name": "CVE-2024-14007 (Shenzhen TVT NVMS-9000 Authentication Bypass)",
        "recency": "recently_disclosed",
        "novelty_impact": "reduces_novelty",
        "confidence": "High",
        "notes": "OSINT confirms CVE-2024-14007 is a recent (2024) and publicly known authentication bypass vulnerability affecting NVMS-9000 firmware. The observed activity directly matches known exploitation patterns for this CVE."
      }
    },
    {
      "candidate_id": "odd-conpot-guardian_ast-1",
      "classification": "ICS/SCADA Reconnaissance",
      "threat_description": "Reconnaissance or exploitation attempts against a simulated industrial control system device.",
      "telemetry_summary": {
        "finding": "10 events were recorded by the Conpot honeypot involving the 'guardian_ast' protocol.",
        "indicators": [
          "honeypot: Conpot",
          "protocol: guardian_ast"
        ]
      },
      "osint_validation": {
        "public_mapping_found": true,
        "mapped_to": "protocol_norm",
        "mapping_name": "Veeder-Root TLS-350 Automated Tank Gauge (guardian_ast protocol emulation)",
        "recency": "established",
        "novelty_impact": "reduces_novelty",
        "confidence": "High",
        "notes": "OSINT confirms that 'guardian_ast' is a protocol emulated by Conpot to mimic a Veeder-Root TLS-350 Automated Tank Gauge. This device is publicly known to have an unauthenticated interface, making it a common target for ICS-focused scanning. The activity is therefore not novel."
      }
    }
  ],
  "excluded_or_deprioritized_activity": [
    {
      "id": "exclusion-ENV-scans-1",
      "reason": "Commodity scanning for sensitive '.env' configuration files."
    },
    {
      "id": "exclusion-SSH-VNC-scanning-1",
      "reason": "High-volume, generic scanning for SSH (22) and VNC (5925, 5926) services."
    },
    {
      "id": "exclusion-CVE-2006-2369-1",
      "reason": "Scanning activity related to a very old (2006) CVE, considered background noise."
    },
    {
      "id": "exclusion-network-anomalies-1",
      "reason": "Generic network protocol anomalies (e.g., broken ACKs, truncated packets) not tied to a specific threat."
    }
  ],
  "diagnostics": {
    "evidence_gaps": "Investigation was significantly hampered by recurring tool errors.",
    "failed_queries": [
      {
        "tool": "kibanna_discover_query",
        "error": "Persistently failed with 'Expected text at 1:71 but found START_ARRAY' for queries against keyword fields (e.g., 'alert.signature', 'path.keyword').",
        "impact": "Prevented retrieval of raw event logs for specific signatures and paths, blocking deeper payload and context analysis."
      },
      {
        "tool": "two_level_terms_aggregated",
        "error": "Intermittently failed on certain keyword field combinations.",
        "impact": "Limited the ability to pivot between different data points, such as finding all IPs associated with a specific ASN or User-Agent."
      }
    ],
    "uninvestigated_leads": "Due to time constraints and tool errors, the lead queue was not fully exhausted. Leads related to ASNs (e.g., AS211443) and secondary source IPs were generated but not pursued in the deep dive phase."
  }
}