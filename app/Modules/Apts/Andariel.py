#dj wip
def get_content():
    return {
        "id": "Andariel",  # APT name
        "url_id": "andariel",  # URL segment APT name all lowercase with _ for spaces
        "title": "Andariel",  # Name of the APT group
        "tags": ["state-sponsored", "North Korean", "cyber espionage", "financial theft"],  # Tags associated with the group
        "description": "Andariel is a North Korean state-sponsored cyber espionage and cybercrime group known for targeting financial institutions, government entities, and defense sectors. The group is believed to operate as a sub-unit of the Lazarus Group and has been involved in espionage, cyber theft, and disruptive attacks.",  # Overview/description of the APT group
        "associated_groups": ["Lazarus Group", "APT38"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0210",  # Campaign ID
                "name": "Financial and Defense Sector Attacks",  # Campaign name
                "first_seen": "2016",  # First seen date
                "last_seen": "2025",  # Last seen date
                "references": [
                    "https://attack.mitre.org/groups/G0136/",
                    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-213a"
                ]  # List of references
            }
        ],
        "techniques": ["T1071", "T1003", "T1059", "T1078", "T1102", "T1486"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "CISA", "KISA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "22 March 2024",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0136/"},
            {"source": "CISA", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-213a"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0136/", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-213a"],  # Additional resources
        "remediation": "Strengthen financial transaction monitoring, implement endpoint detection and response (EDR), and deploy strict access controls to prevent unauthorized system access.",  # Recommended actions to mitigate risks
        "improvements": "Enhance banking security protocols, enforce multi-factor authentication (MFA), and conduct regular audits of network activity.",  # Suggestions for detection and response
        "hunt_steps": ["Analyze network traffic for connections to known North Korean infrastructure", "Monitor financial transactions for anomalies and unauthorized fund transfers"],  # Proactive threat hunting steps
        "expected_outcomes": ["Early detection of financial fraud and cyber theft", "Identification of espionage activities targeting critical defense assets"],  # Expected outcomes
        "false_positive": "Legitimate remote access and financial operations may trigger alerts. Validate access sources and transaction behavior.",  # Known false positives
        "clearing_steps": ["Revoke compromised credentials, block unauthorized financial transactions, and monitor for further intrusions.", "Conduct a forensic investigation into affected systems to identify root causes and prevent recurrence."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
