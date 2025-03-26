#dj wip
def get_content():
    return {
        "id": "APT40",  # APT name
        "url_id": "apt40",  # URL segment APT name all lowercase with _ for spaces
        "title": "APT40 (Leviathan)",  # Name of the APT group
        "tags": ["state-sponsored", "Chinese", "cyber espionage"],  # Tags associated with the group
        "description": "APT40, also known as Leviathan, is a Chinese state-sponsored cyber espionage group that primarily targets maritime, defense, government, and technology sectors. The group is known for exploiting vulnerabilities in public-facing applications to gain initial access and establish persistence.",  # Overview/description of the APT group
        "associated_groups": ["Gadolinium", "KRYPTON"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0105",  # Campaign ID
                "name": "Operation Nautical Tiger",  # Campaign name
                "first_seen": "2014",  # First seen date
                "last_seen": "2023",  # Last seen date
                "references": [
                    "https://attack.mitre.org/groups/G0027/",
                    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-200b"
                ]  # List of references
            }
        ],
        "techniques": ["T1071", "T1133", "T1203", "T1082", "T1059"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "NSA", "CISA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "12 December 2023",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0027/"},
            {"source": "CISA", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-200b"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0027/", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-200b"],  # Additional resources
        "remediation": "Enforce strict web application security, patch public-facing vulnerabilities, and monitor network traffic for signs of exploitation.",  # Recommended actions to mitigate risks
        "improvements": "Deploy web application firewalls (WAFs), enforce strong access control policies, and implement threat intelligence-based defenses.",  # Suggestions for detection and response
        "hunt_steps": ["Monitor for unauthorized access to web-facing services", "Analyze unusual outbound traffic patterns indicating data exfiltration"],  # Proactive threat hunting steps
        "expected_outcomes": ["Early detection of APT40 reconnaissance activities", "Prevention of unauthorized system access and data breaches"],  # Expected outcomes
        "false_positive": "Legitimate remote administration tools and third-party services may generate similar traffic. Investigate anomalies carefully.",  # Known false positives
        "clearing_steps": ["Revoke compromised access credentials, patch exploited vulnerabilities, and remove persistence mechanisms.", "Conduct a comprehensive forensic analysis to identify and mitigate potential backdoors."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }