# dj wip
def get_content():
    return {
        "id": "APT10",  # APT name
        "url_id": "apt10",  # URL segment APT name all lowercase with _ for spaces
        "title": "APT10 (MenuPass Group)",  # Name of the APT group
        "tags": ["state-sponsored", "Chinese", "cyber espionage"],  # Tags associated with the group
        "description": "APT10, also known as MenuPass Group, is a Chinese state-sponsored cyber espionage group known for targeting a variety of industries, including aerospace, government, healthcare, and technology. The group has been linked to extensive global espionage operations, leveraging sophisticated malware and supply chain compromises.",  # Overview/description of the APT group
        "associated_groups": ["Stone Panda", "Red Apollo"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0082",  # Campaign ID
                "name": "Operation Cloud Hopper",  # Campaign name
                "first_seen": "2014",  # First seen date
                "last_seen": "2021",  # Last seen date
                "references": [
                    "https://attack.mitre.org/groups/G0045/",
                    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-200a"
                ]  # List of references
            }
        ],
        "techniques": ["T1071", "T1087", "T1003", "T1059", "T1078"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "NSA", "CISA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "15 October 2023",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0045/"},
            {"source": "CISA", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-200a"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0045/", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-200a"],  # Additional resources
        "remediation": "Strengthen network monitoring, enforce strict access controls, and segment critical assets to prevent lateral movement.",  # Recommended actions to mitigate risks
        "improvements": "Enhance endpoint security, implement multi-factor authentication (MFA), and conduct regular security awareness training.",  # Suggestions for detection and response
        "hunt_steps": ["Analyze network traffic for anomalous data exfiltration patterns", "Monitor for unauthorized remote desktop protocol (RDP) connections"],  # Proactive threat hunting steps
        "expected_outcomes": ["Detection of compromised managed service provider (MSP) infrastructure", "Identification of unauthorized data exfiltration methods"],  # Expected outcomes
        "false_positive": "Legitimate remote access tools and cloud services may generate alerts. Validate suspicious activity through behavioral analysis.",  # Known false positives
        "clearing_steps": ["Revoke compromised credentials, patch vulnerable systems, and block command-and-control (C2) communications.", "Conduct a forensic analysis of impacted assets to identify persistence mechanisms."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }