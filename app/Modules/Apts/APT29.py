#dj wip
def get_content():
    return {
        "id": "APT29",  # APT name
        "url_id": "apt29",  # URL segment APT name all lowercase with _ for spaces
        "title": "APT29",  # Name of the APT group
        "tags": ["state-sponsored", "Russian", "cyber espionage"],  # Tags associated with the group
        "description": "APT29, also known as Cozy Bear, is a Russian state-sponsored cyber espionage group. The group is associated with Russia's intelligence services and is known for targeting government institutions, think tanks, healthcare, and technology firms. APT29 is particularly skilled at stealthy, long-term infiltration and data exfiltration.",  # Overview/description of the APT group
        "associated_groups": ["Cozy Bear", "The Dukes"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0041",  # Campaign ID
                "name": "SolarWinds Supply Chain Attack",  # Campaign name
                "first_seen": "2020",  # First seen date
                "last_seen": "2021",  # Last seen date
                "references": ["https://attack.mitre.org/groups/G0016/", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-148a"]  # List of references
            }
        ],
        "techniques": ["T1071", "T1568", "T1027", "T1070", "T1210"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "NSA", "CISA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "15 August 2023",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0016/"},
            {"source": "CISA", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-148a"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0016/", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-148a"],  # Additional resources
        "remediation": "Enhance endpoint security, restrict administrative privileges, and deploy advanced network monitoring solutions. Regularly audit access logs and enforce multi-factor authentication (MFA).",  # Recommended actions to mitigate risks
        "improvements": "Improve phishing awareness training, implement strict access controls, and enhance security incident response procedures.",  # Suggestions for detection and response
        "hunt_steps": ["Monitor for unusual authentication attempts", "Detect use of stealthy exfiltration techniques used by APT29"],  # Proactive threat hunting steps
        "expected_outcomes": ["Identification of unauthorized network access", "Detection of advanced persistent threats within the infrastructure"],  # Expected outcomes
        "false_positive": "Legitimate remote access tools may generate alerts. Validate anomalies by analyzing traffic patterns and user behavior.",  # Known false positives
        "clearing_steps": ["Identify and isolate compromised accounts, remove persistence mechanisms, and conduct thorough forensic investigations.", "Analyze network logs for signs of ongoing infiltration and take preventive measures."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
