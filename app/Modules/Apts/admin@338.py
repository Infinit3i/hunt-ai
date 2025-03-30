#dj wip
def get_content():
    return {
        "id": "Admin@338",  # APT name
        "url_id": "admin_338",  # URL segment APT name all lowercase with _ for spaces
        "title": "Admin@338",  # Name of the APT group
        "tags": ["state-sponsored", "Chinese", "cyber espionage"],  # Tags associated with the group
        "description": "Admin@338 is a Chinese state-sponsored cyber espionage group known for targeting political, economic, and media entities. The group has been active for years, primarily conducting spear-phishing campaigns to compromise high-value targets globally.",  # Overview/description of the APT group
        "associated_groups": ["APT27", "Emissary Panda"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0091",  # Campaign ID
                "name": "Political Influence Operations",  # Campaign name
                "first_seen": "2013",  # First seen date
                "last_seen": "2021",  # Last seen date
                "references": [
                    "https://attack.mitre.org/groups/G0018/",
                    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-200a"
                ]  # List of references
            }
        ],
        "techniques": ["T1566", "T1071", "T1041", "T1102", "T1203"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "FBI", "CISA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "10 November 2023",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0018/"},
            {"source": "CISA", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-200a"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0018/", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-200a"],  # Additional resources
        "remediation": "Strengthen email security policies, deploy advanced threat protection (ATP) for phishing detection, and monitor for unauthorized remote access.",  # Recommended actions to mitigate risks
        "improvements": "Implement email filtering and sandboxing, enable endpoint detection and response (EDR) solutions, and conduct periodic security audits.",  # Suggestions for detection and response
        "hunt_steps": ["Analyze email logs for suspicious attachments and links", "Monitor command-and-control (C2) traffic associated with known malicious domains"],  # Proactive threat hunting steps
        "expected_outcomes": ["Detection of spear-phishing campaigns", "Identification of compromised user credentials and lateral movement attempts"],  # Expected outcomes
        "false_positive": "Legitimate business email activity may trigger alerts. Validate sender reputation and email headers for anomalies.",  # Known false positives
        "clearing_steps": ["Reset affected email credentials, block phishing domains, and implement email authentication mechanisms (SPF, DKIM, DMARC).", "Conduct forensic analysis of impacted inboxes to identify further compromise."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
