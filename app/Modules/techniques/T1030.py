def get_content():
    return {
        "id": "T1030",  # Tactic Technique ID
        "url_id": "1030",  # URL segment for technique reference
        "title": "Data Transfer Size Limits",  # Name of the attack technique
        "description": "Adversaries may exfiltrate data in fixed size chunks or limit packet sizes below certain thresholds to avoid triggering network data transfer alerts.",  # Simple description (one pair of quotes)
        "tags": [
            "Data Transfer Size Limits",
            "Exfiltration",
            "Packet Size",
            "APT41",
            "ESET ForSSHe December 2018",
            "Rclone",
            "Cobalt Strike",
            "Mythc Documentation",
            "Kaspersky Lyceum October 2021",
            "Mandiant Suspected Turla Campaign February 2023"
        ],  # Up to 10 tags
        "tactic": "Exfiltration",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "Linux, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Analyze network traffic for connections sending fixed-size data packets or operating at lower than expected thresholds",
            "Identify processes that maintain unusually long connections or communicate at consistent intervals",
            "Look for processes that do not typically have network activity but are now sending data"
        ],
        "data_sources": "Network Traffic: Network Connection Creation, Network Traffic: Network Traffic Flow",
        "log_sources": [
            {
                "type": "Network Traffic",
                "source": "Flow Data/Packet Capture",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Network Traffic",
                "location": "Outbound traffic from compromised hosts",
                "identify": "Data exfiltrated in smaller chunks"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Network Traffic",
                "location": "C2 server or external endpoint",
                "identify": "Aggregated data after chunk-based exfiltration"
            }
        ],
        "detection_methods": [
            "Monitor for abnormal volumes of data leaving the network in small, regular intervals",
            "Use deep packet inspection to detect suspicious or non-standard protocols",
            "Correlate endpoint process logs with network traffic to identify unusual data transfer patterns"
        ],
        "apt": [
            "APT41",
            "Turla",
            "Lyceum"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Identify hosts with unexpectedly large outbound traffic patterns broken into small packets",
            "Check process logs for any references to exfiltration or compression utilities",
            "Correlate timeframes of suspicious network traffic with user logon/logoff events"
        ],
        "expected_outcomes": [
            "Detection of stealthy exfiltration attempts using chunk-based transfers",
            "Identification of processes or accounts responsible for the anomalous data flows",
            "Reduced likelihood of missing exfiltration events due to small, consistent transfers"
        ],
        "false_positive": "Legitimate streaming applications or batch processes may also send data in fixed-size chunks. Validate context and usage.",
        "clearing_steps": [
            "Terminate or block the offending process or connection",
            "Isolate the affected system(s) to prevent further data loss",
            "Review logs and recover any exfiltrated data if possible"
        ],
        "mitre_mapping": [
            {
                "tactic": "Exfiltration",
                "technique": "Data Transfer Size Limits (T1030)",
                "example": "Limiting exfiltration packet size to stay under alert thresholds"
            }
        ],
        "watchlist": [
            "Hosts sending consistent small packets over extended periods",
            "Processes with unexpected network usage or traffic patterns",
            "Increased volume of partial file or chunked data transmissions"
        ],
        "enhancements": [
            "Implement anomaly-based network detection to spot unusual packet sizes",
            "Restrict outbound network access to only required services and domains",
            "Use endpoint detection and response (EDR) to correlate process and network behaviors"
        ],
        "summary": "Adversaries can avoid detection by transferring data in small, fixed-size chunks, reducing the likelihood of triggering threshold-based alerts on large or abnormal data transfers.",
        "remediation": "Configure network monitoring to alert on unusual data flow patterns, apply least privilege to limit data access, and review logs for chunk-based exfiltration attempts.",
        "improvements": "Enhance threat intelligence correlation for known chunk-based exfiltration patterns, implement real-time analysis of packet sizes, and routinely audit data egress points."
    }
