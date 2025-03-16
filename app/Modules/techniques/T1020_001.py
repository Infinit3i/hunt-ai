def get_content():
    return {
        "id": "T1020.001",  # Tactic Technique ID
        "url_id": "1020/001",  # URL segment for technique reference
        "title": "Automated Exfiltration: Traffic Duplication",  # Name of the attack technique
        "description": "Adversaries may leverage traffic mirroring in order to automate data exfiltration over compromised infrastructure. Traffic mirroring is a native feature for some devices, often used for network analysis. For example, devices may be configured to forward network traffic to one or more destinations for analysis by a network analyzer or other monitoring device. Adversaries may abuse traffic mirroring to mirror or redirect network traffic through other infrastructure they control. Malicious modifications to network devices to enable traffic redirection may be possible through ROMMONkit or Patch System Image. Many cloud-based environments also support traffic mirroring. For example, AWS Traffic Mirroring, GCP Packet Mirroring, and Azure vTap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to. Adversaries may use traffic duplication in conjunction with Network Sniffing, Input Capture, or Adversary-in-the-Middle depending on the goals and objectives of the adversary.",  
        "tags": [],  
        "tactic": "Exfiltration",  
        "protocol": "IaaS, Network",  
        "os": "",  
        "tips": ["Monitor network traffic for uncommon data flows.", "Analyze packet contents for unexpected protocol behavior."],  
        "data_sources": "Network Traffic: Network Connection Creation, Network Traffic: Network Traffic Flow",  
        "log_sources": [  
            {"type": "Network Traffic", "source": "Firewall", "destination": "Network Monitor"}  
        ],  
        "source_artifacts": [  
            {"type": "Network Packet", "location": "/var/log/network/", "identify": "Captured traffic logs"}  
        ],  
        "destination_artifacts": [  
            {"type": "Network Packet", "location": "/var/log/network_mirror/", "identify": "Mirrored traffic logs"}  
        ],  
        "detection_methods": ["Anomaly detection on network traffic", "Deep packet inspection"],  
        "apt": ["APT19", "APT32"],  
        "spl_query": ["index=network_logs | search traffic_mirror=true"],  
        "hunt_steps": ["Identify unusual traffic patterns.", "Check for unauthorized traffic mirroring rules."],  
        "expected_outcomes": ["Detection of unauthorized network traffic mirroring."],  
        "false_positive": "Legitimate network monitoring tools may trigger alerts.",  
        "clearing_steps": ["Disable unauthorized traffic mirroring.", "Check device configurations for malicious modifications."],  
        "mitre_mapping": [  
            {"tactic": "Exfiltration", "technique": "T1020", "example": "Data exfiltration via traffic mirroring"}  
        ],  
        "watchlist": ["Unusual network destinations", "New traffic mirroring rules"],  
        "enhancements": ["Implement strict network segmentation.", "Use encrypted communication channels."],  
        "summary": "Traffic duplication can be exploited for data exfiltration by adversaries abusing network mirroring capabilities.",  
        "remediation": "Ensure only authorized devices can configure traffic mirroring and monitor logs for unusual traffic behavior.",  
        "improvements": "Use AI-driven anomaly detection to flag unexpected traffic patterns."  
    }
