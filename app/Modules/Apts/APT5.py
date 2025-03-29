# dj wip
def get_content():
    return {
        "id": "APT5",  # APT name
        "url_id": "apt5",  # URL segment APT name all lowercase with _ for spaces
        "title": "APT5 (MANGANESE)",  # Name of the APT group
        "tags": ["state-sponsored", "Chinese", "cyber espionage"],  # Tags associated with the group
        "description": "APT5, also known as MANGANESE, is a Chinese state-sponsored threat group that has been active since at least 2007. The group primarily targets aerospace, defense, and telecommunications sectors, often leveraging supply chain attacks to gain access to their targets.",  # Overview/description of the APT group
        "associated_groups": ["Keyhole Panda"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0105",  # Campaign ID
                "name": "Operation Keyhole",  # Campaign name
                "first_seen": "2016",  # First seen date
                "last_seen": "2022",  # Last seen date
                "references": [
                    "https://attack.mitre.org/groups/G1023/",
                    "https://www.fireeye.com/blog/threat-research/2018/06/chinese-cyber-espionage-apt5.html"
                ]  # List of references
            }
        ],
        "techniques": ["T1190", "T1133", "T1210", "T1078", "T1046"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "FireEye", "NSA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "20 March 2025",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G1023/"},
            {"source": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/2018/06/chinese-cyber-espionage-apt5.html"}
        ],
        "resources": ["https://attack.mitre.org/groups/G1023/", "https://www.fireeye.com/blog/threat-research/2018/06/chinese-cyber-espionage-apt5.html"],  # Additional resources
        "remediation": "Enhance supply chain security, implement strict network segmentation, and monitor for anomalous VPN connections.",  # Recommended actions to mitigate risks
        "improvements": "Deploy robust endpoint detection and response (EDR) solutions, enforce MFA on all remote access points, and conduct regular cyber threat exercises.",  # Suggestions for detection and response
        "hunt_steps": ["Monitor unusual VPN activity", "Analyze supply chain partner network traffic for signs of compromise"],  # Proactive threat hunting steps
        "expected_outcomes": ["Detection of supply chain-related breaches", "Identification of unauthorized access within telecommunications infrastructure"],  # Expected outcomes
        "false_positive": "Legitimate vendor remote access may generate alerts. Correlate with vendor authentication logs to rule out benign events.",  # Known false positives
        "clearing_steps": ["Block malicious IP addresses, reset compromised credentials, and audit third-party access permissions."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
