#dj wip
def get_content():
    return {
        "id": "BlackTech",  # APT name
        "url_id": "blacktech",  # URL segment APT name all lowercase with _ for spaces
        "title": "BlackTech",  # Name of the APT group
        "tags": ["state-sponsored", "Chinese", "cyber espionage"],  # Tags associated with the group
        "description": "BlackTech is a Chinese state-sponsored cyber espionage group known for targeting government, technology, and defense sectors, particularly in East Asia and the United States. The group is highly skilled in stealthy operations, using advanced persistence techniques to maintain long-term access to compromised networks.",  # Overview/description of the APT group
        "associated_groups": ["TA410", "APT41"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0053",  # Campaign ID
                "name": "BlackTech Espionage Operations",  # Campaign name
                "first_seen": "2017",  # First seen date
                "last_seen": "2024",  # Last seen date
                "references": ["https://attack.mitre.org/groups/G0098/", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-277a"]  # List of references
            }
        ],
        "techniques": ["T1071", "T1568", "T1027", "T1070", "T1210"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "NSA", "CISA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "10 September 2023",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0098/"},
            {"source": "CISA", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-277a"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0098/", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-277a"],  # Additional resources
        "remediation": "Implement strong network segmentation, enhance endpoint detection and response (EDR) capabilities, and monitor for unusual remote access activity. Ensure regular patching of vulnerabilities.",  # Recommended actions to mitigate risks
        "improvements": "Strengthen access controls, enforce multi-factor authentication (MFA), and improve cybersecurity awareness training.",  # Suggestions for detection and response
        "hunt_steps": ["Monitor for unauthorized access to sensitive systems", "Detect use of stealthy lateral movement techniques used by BlackTech"],  # Proactive threat hunting steps
        "expected_outcomes": ["Identification of hidden persistence mechanisms", "Detection of unauthorized remote access attempts"],  # Expected outcomes
        "false_positive": "Legitimate administrative tools may generate alerts. Validate anomalies by analyzing behavioral indicators.",  # Known false positives
        "clearing_steps": ["Revoke compromised credentials, isolate affected systems, and remove persistence mechanisms.", "Analyze network logs to identify and block unauthorized access pathways."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
