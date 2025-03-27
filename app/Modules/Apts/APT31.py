#dj wip
# APT31 work in progress
def get_content():
    return {
        "id": "APT31",  # APT name
        "url_id": "apt31",  # URL segment APT name all lowercase with _ for spaces
        "title": "APT31",  # Name of the APT group
        "tags": ["state-sponsored", "Chinese", "cyber espionage"],  # Tags associated with the group
        "description": "APT31, also known as Zirconium, is a Chinese state-sponsored cyber espionage group known for targeting governmental, defense, and critical infrastructure organizations. The group is known for extensive phishing campaigns and sophisticated malware deployments.",  # Overview/description of the APT group
        "associated_groups": ["APT10", "APT40"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0045",  # Campaign ID
                "name": "Zirconium Espionage Operations",  # Campaign name
                "first_seen": "2017",  # First seen date
                "last_seen": "2024",  # Last seen date
                "references": ["https://attack.mitre.org/groups/G0116/", "https://www.fireeye.com/blog/threat-research/2020/10/chinese-apt31-espionage-operations.html"]  # List of references
            }
        ],
        "techniques": ["T1566", "T1105", "T1071", "T1203", "T1055"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "FireEye", "Microsoft"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "18 June 2023",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0116/"},
            {"source": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/2020/10/chinese-apt31-espionage-operations.html"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0116/", "https://www.fireeye.com/blog/threat-research/2020/10/chinese-apt31-espionage-operations.html"],  # Additional resources
        "remediation": "Implement phishing-resistant MFA, monitor for unusual user behavior, and deploy endpoint detection and response (EDR) solutions. Regularly update and patch vulnerable systems.",  # Recommended actions to mitigate risks
        "improvements": "Increase threat intelligence sharing, conduct red team assessments, and implement strong network segmentation.",  # Suggestions for detection and response
        "hunt_steps": ["Monitor for large-scale phishing campaigns", "Identify unauthorized cloud service access"],  # Proactive threat hunting steps
        "expected_outcomes": ["Early detection of phishing campaigns", "Prevention of unauthorized data access"],  # Expected outcomes
        "false_positive": "Legitimate cloud logins from new locations may trigger alerts. Analyze user behavior and access patterns to confirm threats.",  # Known false positives
        "clearing_steps": ["Reset compromised accounts, review system logs for unauthorized changes, and remove identified malware.", "Enhance email filtering and improve security awareness training."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
