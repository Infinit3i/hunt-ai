#dj wip
def get_content():
    return {
        "id": "APT-C-23",  # APT name
        "url_id": "apt_c_23",  # URL segment APT name all lowercase with _ for spaces
        "title": "APT-C-23 (Two-Tailed Scorpion)",  # Name of the APT group
        "tags": ["state-sponsored", "Middle Eastern", "cyber espionage", "mobile malware"],  # Tags associated with the group
        "description": "APT-C-23, also known as Two-Tailed Scorpion, is a cyber espionage group known for targeting Middle Eastern military, government, and media organizations. The group is particularly notable for its use of Android and Windows malware to conduct surveillance operations.",  # Overview/description of the APT group
        "associated_groups": ["Arid Viper", "Desert Falcons"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0240",  # Campaign ID
                "name": "Mobile and Desktop Espionage Operations",  # Campaign name
                "first_seen": "2017",  # First seen date
                "last_seen": "2024",  # Last seen date
                "references": [
                    "https://attack.mitre.org/groups/G0023/",
                    "https://www.checkpoint.com/research/apt-c-23-mobile-espionage-in-the-middle-east/"
                ]  # List of references
            }
        ],
        "techniques": ["T1406", "T1071", "T1203", "T1566", "T1102"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "Check Point", "CISA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "28 March 2024",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0023/"},
            {"source": "Check Point", "url": "https://www.checkpoint.com/research/apt-c-23-mobile-espionage-in-the-middle-east/"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0023/", "https://www.checkpoint.com/research/apt-c-23-mobile-espionage-in-the-middle-east/"],  # Additional resources
        "remediation": "Strengthen mobile security policies, enforce app whitelisting, and deploy endpoint detection and response (EDR) solutions for mobile and desktop environments.",  # Recommended actions to mitigate risks
        "improvements": "Increase monitoring of mobile network traffic, educate users on social engineering tactics, and enforce multi-factor authentication (MFA).",  # Suggestions for detection and response
        "hunt_steps": ["Analyze mobile network traffic for connections to known malicious infrastructure", "Monitor for unauthorized access to sensitive mobile and desktop applications"],  # Proactive threat hunting steps
        "expected_outcomes": ["Detection of mobile malware infections", "Identification of unauthorized surveillance activities"],  # Expected outcomes
        "false_positive": "Legitimate remote access applications and enterprise mobile management tools may generate alerts. Verify behavioral anomalies.",  # Known false positives
        "clearing_steps": ["Remove malicious applications from infected devices, reset compromised accounts, and block identified command-and-control (C2) domains.", "Conduct forensic analysis of infected mobile and desktop devices to identify persistence mechanisms."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
