#dj wip
# APT12 work in progress
def get_content():
    return {
        "id": "APT12",  # APT name
        "url_id": "apt12",  # URL segment APT name all lowercase with _ for spaces
        "title": "APT12",  # Name of the APT group
        "tags": ["state-sponsored", "Chinese", "cyber espionage"],  # Tags associated with the group
        "description": "APT12, also known as Numbered Panda, is a Chinese state-sponsored cyber espionage group known for targeting media organizations, defense industries, and governmental entities. The group is known for its persistent phishing campaigns and advanced backdoor deployments.",  # Overview/description of the APT group
        "associated_groups": ["APT10", "APT17"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0029",  # Campaign ID
                "name": "Numbered Panda Attacks",  # Campaign name
                "first_seen": "2012",  # First seen date
                "last_seen": "2023",  # Last seen date
                "references": ["https://attack.mitre.org/groups/G0005/", "https://www.fireeye.com/blog/threat-research/2013/03/china-based-espionage-apt12.html"]  # List of references
            }
        ],
        "techniques": ["T1566", "T1105", "T1071", "T1003", "T1036"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "FireEye", "CISA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "20 July 2023",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0005/"},
            {"source": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/2013/03/china-based-espionage-apt12.html"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0005/", "https://www.fireeye.com/blog/threat-research/2013/03/china-based-espionage-apt12.html"],  # Additional resources
        "remediation": "Enhance email filtering, deploy advanced endpoint protection, and conduct employee cybersecurity training. Regularly update security patches and enforce least privilege access controls.",  # Recommended actions to mitigate risks
        "improvements": "Increase threat intelligence sharing, conduct proactive security assessments, and implement behavioral-based anomaly detection.",  # Suggestions for detection and response
        "hunt_steps": ["Monitor for spear-phishing attempts targeting media organizations", "Identify unauthorized exfiltration of sensitive data"],  # Proactive threat hunting steps
        "expected_outcomes": ["Early detection of phishing campaigns", "Prevention of unauthorized data exfiltration"],  # Expected outcomes
        "false_positive": "Legitimate email communication with attachments may trigger alerts. Validate based on sender reputation and behavioral context.",  # Known false positives
        "clearing_steps": ["Reset compromised credentials, review email gateways for unauthorized activity, and remove identified malware.", "Enhance monitoring of outbound network traffic for unusual data transfers."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
