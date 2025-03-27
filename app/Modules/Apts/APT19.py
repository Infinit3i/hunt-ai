#dj wip
# APT19 work in progress
def get_content():
    return {
        "id": "APT19",  # APT name
        "url_id": "apt19",  # URL segment APT name all lowercase with _ for spaces
        "title": "APT19",  # Name of the APT group
        "tags": ["state-sponsored", "Chinese", "cyber espionage"],  # Tags associated with the group
        "description": "APT19, also known as Deep Panda, is a Chinese state-sponsored cyber espionage group known for targeting law firms, technology companies, and government entities. The group specializes in spear-phishing attacks and leveraging web application vulnerabilities to gain persistent access.",  # Overview/description of the APT group
        "associated_groups": ["APT10", "APT17"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0034",  # Campaign ID
                "name": "Deep Panda Operations",  # Campaign name
                "first_seen": "2014",  # First seen date
                "last_seen": "2023",  # Last seen date
                "references": ["https://attack.mitre.org/groups/G0077/", "https://www.fireeye.com/blog/threat-research/2015/07/deep_panda_us_gov.html"]  # List of references
            }
        ],
        "techniques": ["T1566", "T1105", "T1071", "T1059", "T1190"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "FireEye", "CISA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "15 August 2023",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0077/"},
            {"source": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/2015/07/deep_panda_us_gov.html"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0077/", "https://www.fireeye.com/blog/threat-research/2015/07/deep_panda_us_gov.html"],  # Additional resources
        "remediation": "Enhance perimeter security, deploy web application firewalls, and restrict remote administrative access. Regularly update software and conduct penetration testing.",  # Recommended actions to mitigate risks
        "improvements": "Increase monitoring of spear-phishing campaigns, implement behavioral analytics for anomaly detection, and conduct routine security assessments.",  # Suggestions for detection and response
        "hunt_steps": ["Monitor for suspicious login attempts to web applications", "Identify unauthorized access to sensitive corporate resources"],  # Proactive threat hunting steps
        "expected_outcomes": ["Early detection of phishing campaigns", "Prevention of web-based exploitation attempts"],  # Expected outcomes
        "false_positive": "Legitimate remote access activity may trigger alerts. Validate through behavioral patterns and contextual analysis.",  # Known false positives
        "clearing_steps": ["Reset compromised accounts, review system logs for unauthorized activity, and remove identified malware.", "Enhance monitoring of outbound network traffic for unusual data transfers."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
