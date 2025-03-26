#dj wip
def get_content():
    return {
        "id": "APT27",  # APT name
        "url_id": "apt27",  # URL segment APT name all lowercase with _ for spaces
        "title": "APT27 (Emissary Panda)",  # Name of the APT group
        "tags": ["state-sponsored", "Chinese", "cyber espionage"],  # Tags associated with the group
        "description": "APT27, also known as Emissary Panda, is a Chinese state-sponsored cyber espionage group known for targeting government, technology, defense, and financial sectors. The group is highly sophisticated, employing custom malware and leveraging stolen credentials to maintain long-term access to compromised environments.",  # Overview/description of the APT group
        "associated_groups": ["LuckyMouse", "Iron Tiger"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0091",  # Campaign ID
                "name": "Operation Iron Tiger",  # Campaign name
                "first_seen": "2013",  # First seen date
                "last_seen": "2024",  # Last seen date
                "references": [
                    "https://attack.mitre.org/groups/G0013/",
                    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-066a"
                ]  # List of references
            }
        ],
        "techniques": ["T1071", "T1003", "T1059", "T1021", "T1078"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "NSA", "CISA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "5 November 2023",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0013/"},
            {"source": "CISA", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-066a"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0013/", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-066a"],  # Additional resources
        "remediation": "Monitor and restrict remote desktop protocol (RDP) access, implement endpoint detection and response (EDR) solutions, and apply timely security patches.",  # Recommended actions to mitigate risks
        "improvements": "Enhance privileged access management (PAM), enforce multi-factor authentication (MFA), and conduct red teaming exercises.",  # Suggestions for detection and response
        "hunt_steps": ["Identify suspicious logins from compromised credentials", "Monitor for abnormal outbound connections indicating data exfiltration"],  # Proactive threat hunting steps
        "expected_outcomes": ["Detection of unauthorized credential usage", "Identification of hidden persistence mechanisms"],  # Expected outcomes
        "false_positive": "Legitimate remote access activities may trigger alerts. Investigate anomalies based on behavioral patterns and context.",  # Known false positives
        "clearing_steps": ["Revoke compromised credentials, isolate affected systems, and remove persistence mechanisms.", "Analyze network logs to identify and block unauthorized access pathways."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }