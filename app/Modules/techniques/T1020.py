def get_content():
    return {
        "id": "T1020",
        "url_id": "1020",
        "title": "Automated Exfiltration",
        "description": "Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection. When automated exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as Exfiltration Over C2 Channel and Exfiltration Over Alternative Protocol.",
        "tags": ["Exfiltration", "Automated Processing"],
        "tactic": "Exfiltration",
        "protocol": "Various",
        "os": "Linux, Network, Windows, macOS",
        "tips": [
            "Monitor process file access patterns and network behavior.",
            "Unrecognized processes or scripts that appear to be traversing file systems and sending network traffic may be suspicious."
        ],
        "data_sources": "Command Execution, File Access, Network Connection Creation, Network Traffic Content, Network Traffic Flow, Script Execution",
        "log_sources": [
            {"type": "Command", "source": "Execution", "destination": "Monitoring"},
            {"type": "File", "source": "Access", "destination": "Detection"},
            {"type": "Network Traffic", "source": "Connection Creation", "destination": "Alerting"}
        ],
        "source_artifacts": [
            {"type": "File", "location": "/tmp/exfil_data", "identify": "Contains sensitive data"}
        ],
        "destination_artifacts": [
            {"type": "Network", "location": "Remote C2 server", "identify": "Exfiltrated data"}
        ],
        "detection_methods": ["File Integrity Monitoring", "Network Anomaly Detection", "Behavioral Analysis"],
        "apt": ["Gamaredon Group", "Sidewinder"],
        "spl_query": [
            "| search process_name=unknown_script OR unusual_file_access",
            "| search network_traffic anomalous_transfer"
        ],
        "hunt_steps": [
            "Review network logs for large data transfers.",
            "Identify unexpected file access activities on critical systems."
        ],
        "expected_outcomes": ["Detection of automated data exfiltration attempts", "Identification of adversary behavior"],
        "false_positive": "Automated backups or legitimate large file transfers may trigger alerts.",
        "clearing_steps": [
            "Terminate the malicious process handling exfiltration.",
            "Block outbound connections to identified C2 servers."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1041", "example": "Exfiltration Over C2 Channel"},
            {"tactic": "Exfiltration", "technique": "T1048", "example": "Exfiltration Over Alternative Protocol"}
        ],
        "watchlist": ["Unusual file transfers", "High bandwidth usage from unexpected processes"],
        "enhancements": ["Use endpoint detection solutions to monitor process activity.", "Deploy network intrusion detection systems to identify anomalies."],
        "summary": "Automated Exfiltration enables adversaries to stealthily transfer sensitive data using automated techniques, often leveraging existing exfiltration methods.",
        "remediation": "Isolate the affected system, block malicious network traffic, and update security policies to detect anomalous file access.",
        "improvements": "Enhance anomaly detection capabilities with machine learning-based models."  
    }
