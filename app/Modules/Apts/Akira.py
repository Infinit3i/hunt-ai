#dj wip
def get_content():
    return {
        "id": "Akira",  # APT name
        "url_id": "akira",  # URL segment APT name all lowercase with _ for spaces
        "title": "Akira Ransomware Group",  # Name of the APT group
        "tags": ["ransomware", "cybercriminal", "data extortion"],  # Tags associated with the group
        "description": "Akira is a cybercriminal group known for operating a ransomware-as-a-service (RaaS) model, targeting various industries worldwide. The group encrypts files and demands ransom payments, often threatening to leak stolen data if victims refuse to pay.",  # Overview/description of the APT group
        "associated_groups": ["Conti", "LockBit"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0178",  # Campaign ID
                "name": "Akira Ransomware Operations",  # Campaign name
                "first_seen": "2023",  # First seen date
                "last_seen": "2025",  # Last seen date
                "references": [
                    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-201a",
                    "https://attack.mitre.org/groups/GXXXX/"
                ]  # List of references
            }
        ],
        "techniques": ["T1486", "T1566", "T1071", "T1203", "T1027"],  # List of techniques employed by this APT group
        "contributors": ["CISA", "FBI", "MITRE"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "12 February 2024",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "CISA", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-201a"},
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/GXXXX/"}
        ],
        "resources": ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-201a", "https://attack.mitre.org/groups/GXXXX/"],  # Additional resources
        "remediation": "Implement robust backup strategies, deploy endpoint detection and response (EDR) solutions, and restrict administrative privileges to minimize ransomware impact.",  # Recommended actions to mitigate risks
        "improvements": "Enhance phishing awareness training, enable multi-factor authentication (MFA), and conduct regular security assessments.",  # Suggestions for detection and response
        "hunt_steps": ["Analyze network traffic for anomalous connections to ransomware command-and-control (C2) servers", "Monitor for mass file encryption events and unauthorized privileged access"],  # Proactive threat hunting steps
        "expected_outcomes": ["Early detection of ransomware deployment", "Identification of initial access vectors and lateral movement"],  # Expected outcomes
        "false_positive": "Legitimate encryption software may trigger alerts. Verify the origin and intent of encryption activities.",  # Known false positives
        "clearing_steps": ["Isolate infected machines, restore data from secure backups, and block known ransomware-associated domains and IPs.", "Conduct a forensic investigation to determine root cause and prevent future attacks."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
