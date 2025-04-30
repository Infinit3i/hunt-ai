#dj wip 
def get_content():
    return {
        "id": "LazarusGroup",  # APT name
        "url_id": "Lazarus_Group",  # URL segment APT name all lowercase with _ for spaces
        "title": "Lazarus Group",  # Name of the APT group
        "tags": ["state-sponsored", "North Korean", "cyber espionage", "financial crimes"],  # Tags associated with the group
        "description": "Lazarus Group is a North Korean state-sponsored cyber espionage and financial crime organization. The group is known for high-profile cyber attacks, including bank heists, ransomware campaigns, and espionage activities against government and corporate entities worldwide.",  # Overview/description of the APT group
        "associated_groups": ["APT38", "Hidden Cobra"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0032",  # Campaign ID
                "name": "Operation Dark Seoul",  # Campaign name
                "first_seen": "2013",  # First seen date
                "last_seen": "2019",  # Last seen date
                "references": ["https://attack.mitre.org/groups/G0032/", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a"]  # List of references
            }
        ],
        "techniques": ["T1071", "T1003", "T1059", "T1562", "T1027"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "CISA", "Kaspersky"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "10 July 2023",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0032/"},
            {"source": "CISA", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0032/", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a"],  # Additional resources
        "remediation": "Deploy advanced threat detection, limit privilege escalation, and implement strong authentication mechanisms. Regularly update security patches and monitor financial transactions for anomalies.",  # Recommended actions to mitigate risks
        "improvements": "Enhance security awareness training, deploy endpoint detection and response (EDR) solutions, and establish robust financial transaction monitoring.",  # Suggestions for detection and response
        "hunt_steps": ["Monitor for unusual financial transactions", "Detect usage of custom malware strains linked to Lazarus Group"],  # Proactive threat hunting steps
        "expected_outcomes": ["Identification of unauthorized transactions", "Detection of compromised systems used in espionage or financial crime"],  # Expected outcomes
        "false_positive": "Legitimate financial transactions and remote administration tools may trigger alerts. Ensure contextual validation before responding to incidents.",  # Known false positives
        "clearing_steps": ["Investigate compromised financial accounts, reset affected credentials, and conduct forensic analysis to remove persistence mechanisms.", "Review logs to identify unauthorized access points and shut down any detected backdoors."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
