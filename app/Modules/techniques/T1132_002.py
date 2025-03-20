def get_content():
    return {
        "id": "T1132.002",  # Tactic Technique ID
        "url_id": "1132/002",  # URL segment for technique reference
        "title": "Data Encoding: Non-Standard Encoding",  # Name of the attack technique
        "description": "Adversaries may use a non-standard data encoding system, such as modified Base64, to make C2 traffic more difficult to detect by diverging from standard protocol specifications.",  # Simple description (one pair of quotes)
        "tags": [
            "Data Encoding",
            "Non-Standard Encoding",
            "Command and Control",
            "Wikipedia Binary-to-text Encoding",
            "Wikipedia Character Encoding",
            "University of Birmingham C2",
            "McAfee Oceansalt Oct 2018",
            "ESET InvisiMole June 2020",
            "Mandiant ROADSWEEP August 2022",
            "Securelist ShadowPad Aug 2017",
            "NCSC Cyclops Blink February 2022",
            "Kaspersky ToddyCat June 2022",
            "McAfee Bankshot",
            "CYBERCOM Iranian Intel Cyber January 2022",
            "FireEye APT30",
            "DHS CISA AA22-055A MuddyWater February 2022",
            "NCSC GCHQ Small Sieve Jan 2022",
            "MoustachedBouncer ESET August 2023",
            "Joint Cybersecurity Advisory AA23-129A Snake Malware May 2023",
            "Unit42 RDAT July 2020"
        ],
        "tactic": "Command and Control",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "Linux, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives)",
            "Look for processes utilizing the network that do not normally communicate or have never been seen before",
            "Analyze packet contents to detect communications that do not follow expected protocol behavior for the port in use"
        ],
        "data_sources": "Network Traffic: Network Traffic Content",  # Data sources
        "log_sources": [
            {
                "type": "Network Traffic",
                "source": "Packet Capture or Flow Data",
                "destination": "SIEM or IDS"
            }
        ],
        "source_artifacts": [
            {"type": "", "location": "", "identify": ""}
        ],
        "destination_artifacts": [
            {"type": "", "location": "", "identify": ""}
        ],
        "detection_methods": [
            "Use deep packet inspection to identify unusual or custom encoding schemes",
            "Monitor for unexpected protocol usage or anomalies in data length/structure",
            "Correlate suspicious processes sending/receiving large volumes of encoded data"
        ],
        "apt": [
            "APT30",
            "MuddyWater",
            "ToddyCat"
        ],
        "spl_query": [],
        "hunt_steps": [],
        "expected_outcomes": [],
        "false_positive": "Legitimate applications may occasionally use custom encoding for specialized data transfer. Validate context and necessity.",
        "clearing_steps": [],
        "mitre_mapping": [
            {
                "tactic": "Command and Control",
                "technique": "Data Encoding",
                "example": "Use of modified Base64 to obfuscate C2 traffic"
            }
        ],
        "watchlist": [],
        "enhancements": [],
        "summary": "Non-standard data encoding can mask malicious C2 traffic by deviating from known protocol specifications, complicating detection.",
        "remediation": "Implement network monitoring and deep packet inspection to detect unusual encoding. Restrict processes or ports that commonly exhibit custom encoding.",
        "improvements": "Regularly review network traffic patterns, refine anomaly-based detection rules, and correlate endpoint logs to identify suspicious encoding activity."
    }
