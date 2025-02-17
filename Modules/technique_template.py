def get_content():
    return {
        "id": "",  # Tactic Technique ID (e.g., T1556.001)
        "url_id": "",  # URL segment for technique reference (e.g., 1556/001)
        "title": "",  # Name of the attack technique
        "tactic": "",  # Associated MITRE ATT&CK tactic
        "data_sources": "",  # Data sources required for detection
        "protocol": "",  # Protocol used in the attack technique
        "os": "",  # Targeted operating systems
        "objective": "",  # Purpose of adversary using this technique
        "scope": "",  # Scope of monitoring and investigation
        "threat_model": "",  # Threat model describing potential adversary behaviors
        "hypothesis": [],  # Questions to ask during threat hunting
        "tips": [],  # Additional investigation and mitigation tips
        "log_sources": [  # Logs necessary for detection
            {"type": "", "source": "", "destination": ""}
        ],
        "source_artifacts": [  # Artifacts generated on the source machine
            {"type": "", "location": "", "identify": ""}
        ],
        "destination_artifacts": [  # Artifacts generated on the destination machine
            {"type": "", "location": "", "identify": ""}
        ],
        "detection_methods": [],  # Techniques for identifying the attack
        "apt": [], # APT groups known to use this technique typically start with G#### (e.g., G0016) - do not show the S#### - show the name of the APT not G####
        "spl_query": [],  # Splunk queries to detect the technique, multiple can be added. for | use \n| - this should be taken literal not putt in on your own
        "hunt_steps": [],  # Steps to proactively hunt for threats
        "expected_outcomes": [],  # Expected results from detection/hunting
        "false_positive": "",  # Known false positives and how to handle them
        "clearing_steps": [],  # Steps for remediation and clearing traces - do commands also on machines locally
        "mitre_mapping": [  # Next Mitre Technique that could be used after this technique
            {"tactic": "", "technique": "", "example": ""}
        ],
        "watchlist": [],  # Indicators to monitor for potential threats
        "enhancements": [],  # Suggested improvements to detection
        "summary": "",  # High-level summary of the technique
        "remediation": "",  # Recommended actions to mitigate risk
        "improvements": ""  # Suggested ways to improve detection and response
    }

