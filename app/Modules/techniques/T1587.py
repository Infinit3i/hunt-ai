def get_content():
    return {
        "id": "T1587",  # Tactic Technique ID
        "url_id": "1587",  # URL segment for technique reference
        "title": "Develop Capabilities",  # Name of the attack technique
        "description": "Adversaries may build capabilities to use during targeting, such as custom malware, exploits, or self-signed certificates. They may do so in-house or via contractors, tailoring requirements to support various phases of an intrusion.",  # Simple description
        "tags": [
            "Develop Capabilities",
            "Custom Malware",
            "Exploit Development",
            "Resource Development",
            "Self-Signed Certificates",
            "APT1",
            "Sofacy",
            "Bitdefender StrongPity",
            "Talos Promethium",
            "Moonstone Sleet"
        ],
        "tactic": "Resource Development",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "N/A",  # Pre-ATT&CK / Not OS-specific
        "tips": [
            "Analyze malware for compiler artifacts, debugging indicators, or code overlaps",
            "Leverage malware repositories to identify additional samples and track adversary development patterns",
            "Monitor certificate usage and pivot on certificate metadata to discover related infrastructure"
        ],
        "data_sources": "Internet Scan: Response Content, Malware Repository: Malware Content, Malware Repository: Malware Metadata",
        "log_sources": [
            {
                "type": "Internet Scan",
                "source": "Domain/Certificate Monitoring",
                "destination": "SIEM"
            },
            {
                "type": "Malware Repository",
                "source": "Malware Samples/Metadata",
                "destination": "Threat Intelligence Platform"
            }
        ],
        "source_artifacts": [
            {
                "type": "Development Artifacts",
                "location": "Adversary or contractor environment",
                "identify": "Custom malware source code, exploits, certificates"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Operational Capabilities",
                "location": "Adversary infrastructure or distribution channels",
                "identify": "Packaged malware, compiled exploits, signed binaries"
            }
        ],
        "detection_methods": [
            "Focus on code similarities or debugging artifacts in discovered malware",
            "Correlate or pivot on certificate metadata to identify additional adversary infrastructure",
            "Analyze discovered malware for unique development or compilation patterns"
        ],
        "apt": [
            "APT1",
            "Sofacy",
            "StrongPity",
            "Promethium",
            "Moonstone Sleet"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Pivot on code reuse or function signatures in known malware samples",
            "Track certificate usage across multiple domains for suspicious overlaps",
            "Identify newly observed exploits or features in adversary toolsets"
        ],
        "expected_outcomes": [
            "Insight into adversary development processes and patterns",
            "Identification of new or emerging adversary malware capabilities",
            "Potential correlation of malware samples to a single developer or group"
        ],
        "false_positive": "Legitimate software developers or security researchers may exhibit similar behaviors when building or testing tools. Validate context and ownership.",
        "clearing_steps": [
            "N/A (This activity occurs outside victim visibility; clearing steps may not apply in the victim environment)"
        ],
        "mitre_mapping": [
            {
                "tactic": "Resource Development",
                "technique": "Develop Capabilities (T1587)",
                "example": "Creating custom malware, exploits, or self-signed certificates tailored to adversary needs"
            }
     
