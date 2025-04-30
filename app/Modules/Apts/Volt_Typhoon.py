#dj work in progress
def get_content():
    return {
        "id": "VoltTyphoon",  # APT name
        "url_id": "Volt_Typhoon",  # URL segment APT name all lowercase with _ for spaces
        "title": "Volt Typhoon",  # Name of the APT group
        "tags": ["state-sponsored", "Chinese", "cyber espionage"],  # Tags associated with the group
        "description": "Volt Typhoon is a Chinese state-sponsored cyber espionage group known for targeting critical infrastructure, including military, government, and telecommunications sectors. The group is highly skilled in maintaining persistent access and operates with a strong focus on stealth.",  # Overview/description of the APT group
        "associated_groups": ["APT40", "APT41"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0025",  # Campaign ID
                "name": "Volt Typhoon Intrusions",  # Campaign name
                "first_seen": "2021",  # First seen date
                "last_seen": "2024",  # Last seen date
                "references": ["https://attack.mitre.org/groups/G0141/", "https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-china-sponsored-actor-living-off-the-land-to-target-crititcal-infrastructure/" ]  # List of references
            }
        ],
        "techniques": ["T1071", "T1003", "T1059", "T1562", "T1210"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "Microsoft", "CISA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "15 June 2023",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0141/"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-china-sponsored-actor-living-off-the-land-to-target-crititcal-infrastructure/"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0141/", "https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-china-sponsored-actor-living-off-the-land-to-target-crititcal-infrastructure/"],  # Additional resources
        "remediation": "Implement strict access control, monitor network traffic for lateral movement, and deploy endpoint detection and response (EDR) solutions. Regularly update software and patch vulnerabilities.",  # Recommended actions to mitigate risks
        "improvements": "Increase logging and monitoring, use behavioral analytics to detect suspicious activity, and educate employees on social engineering threats.",  # Suggestions for detection and response
        "hunt_steps": ["Monitor for unusual network connections to critical infrastructure", "Look for signs of credential theft or privilege escalation techniques"],  # Proactive threat hunting steps
        "expected_outcomes": ["Detection of unauthorized remote access", "Identification of lateral movement within the network"],  # Expected outcomes
        "false_positive": "Legitimate administrative tools may trigger alerts. Validate anomalies by assessing context and behavioral indicators.",  # Known false positives
        "clearing_steps": ["Revoke compromised credentials, isolate affected systems, and perform forensic analysis to identify persistence mechanisms.", "Review logs and remove any unauthorized accounts or backdoors."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
