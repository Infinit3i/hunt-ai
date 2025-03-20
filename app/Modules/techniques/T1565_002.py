def get_content():
    return {
        "id": "T1565.002",  # Tactic Technique ID
        "url_id": "1565/002",  # URL segment for technique reference
        "title": "Data Manipulation: Transmitted Data Manipulation",  # Name of the attack technique
        "description": "Adversaries may alter data en route to storage or other systems in order to manipulate external outcomes or hide activity, thus threatening data integrity. They may intercept data over network connections or between processes, requiring specialized expertise and potentially prolonged reconnaissance to achieve desired effects.",  # Simple description
        "tags": [
            "Data Manipulation",
            "Transmitted Data Manipulation",
            "Integrity",
            "Network Traffic",
            "OS API Execution",
            "FireEye APT38 Oct 2018",
            "DOJ Lazarus Sony 2018",
            "Securelist Brazilian Banking Malware July 2020",
            "ESET Casbaneiro Oct 2019",
            "Fortinet Metamorfo Feb 2020"
        ],  # Up to 10 tags
        "tactic": "Impact",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "Linux, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Use file hashing or checksums on critical files as they transit a network",
            "Perform manual or out-of-band integrity checks for critical processes and data",
            "Monitor for suspicious or unauthorized interceptors that modify data in transit"
        ],
        "data_sources": "Network Traffic: Network Traffic Content, Network Traffic: Network Traffic Flow, Process: OS API Execution",
        "log_sources": [
            {
                "type": "Network Traffic",
                "source": "Packet Capture or Flow Data",
                "destination": "SIEM"
            },
            {
                "type": "Process",
                "source": "Endpoint Monitoring",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Network Traffic",
                "location": "On-wire data or memory buffers",
                "identify": "Intercepted transmissions"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Network Traffic",
                "location": "Receiving system or process",
                "identify": "Tampered data"
            }
        ],
        "detection_methods": [
            "Network traffic analysis to detect unexpected or manipulated data",
            "Checksum or cryptographic integrity checks for critical transmissions",
            "Monitoring OS or application logs for suspicious API calls intercepting data"
        ],
        "apt": [
            "APT38",
            "Lazarus"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Examine network traffic logs for anomalies or potential tampering",
            "Correlate process logs with network flows to detect interception tools",
            "Validate cryptographic signatures or checksums for data in transit"
        ],
        "expected_outcomes": [
            "Detection of unauthorized modifications to data in transit",
            "Identification of suspicious processes intercepting or rewriting data",
            "Confirmation of data integrity in critical communication channels"
        ],
        "false_positive": "Legitimate traffic manipulation by security solutions (e.g., proxies, load balancers) may appear suspicious. Validate context with known infrastructure and authorized services.",
        "clearing_steps": [
            "Remove or disable malicious interceptors or unauthorized tools",
            "Restore any altered data from known good backups or verified sources",
            "Strengthen network encryption and monitoring to prevent future tampering"
        ],
        "mitre_mapping": [
            {
                "tactic": "Impact",
                "technique": "Data Manipulation (T1565)",
                "example": "Adversaries intercept and modify data packets in transit to conceal malicious activity or mislead recipients"
            }
        ],
        "watchlist": [
            "Abnormal or repeated failed checksums on critical data transmissions",
            "Suspicious processes hooking network APIs or intercepting traffic",
            "Network traffic anomalies on sensitive ports or protocols"
        ],
        "enhancements": [
            "Implement end-to-end encryption with robust integrity checks for critical data",
            "Enable deep packet inspection (DPI) on critical network segments"
        ],
        "summary": "Transmitted data manipulation can alter how information is received or stored, potentially impacting business processes, decision making, and the accuracy of system records.",
        "remediation": "Deploy strong encryption and integrity validation measures for critical transmissions. Regularly audit network flows and endpoint processes to detect unauthorized data interceptors.",
        "improvements": "Increase logging granularity for network traffic, implement anomaly-based detection, and train personnel on recognizing signs of in-transit data tampering."
    }
