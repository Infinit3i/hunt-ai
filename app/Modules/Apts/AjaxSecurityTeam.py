#dj wip
def get_content():
    return {
        "id": "Ajax Security Team",  # APT name
        "url_id": "ajax_security_team",  # URL segment APT name all lowercase with _ for spaces
        "title": "Ajax Security Team",  # Name of the APT group
        "tags": ["hacktivist", "Iranian", "cyber espionage", "defacement"],  # Tags associated with the group
        "description": "Ajax Security Team is an Iranian hacktivist group known for conducting cyber espionage, website defacements, and politically motivated cyber operations. While originally known for defacement campaigns, the group has since evolved into more sophisticated cyber espionage activities.",  # Overview/description of the APT group
        "associated_groups": ["Charming Kitten", "APT35"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0145",  # Campaign ID
                "name": "Operation Sima",  # Campaign name
                "first_seen": "2015",  # First seen date
                "last_seen": "2021",  # Last seen date
                "references": [
                    "https://attack.mitre.org/groups/G0132/",
                    "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/spear-phishing-threat-group.pdf"
                ]  # List of references
            }
        ],
        "techniques": ["T1566", "T1071", "T1102", "T1203", "T1499"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "FireEye", "CISA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "10 January 2024",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0132/"},
            {"source": "FireEye", "url": "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/spear-phishing-threat-group.pdf"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0132/", "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/spear-phishing-threat-group.pdf"],  # Additional resources
        "remediation": "Enhance web application security, monitor for unauthorized web defacement, and conduct penetration testing to identify vulnerabilities.",  # Recommended actions to mitigate risks
        "improvements": "Implement web application firewalls (WAFs), enforce strong authentication mechanisms, and restrict access to website administration portals.",  # Suggestions for detection and response
        "hunt_steps": ["Analyze web server logs for unauthorized modifications", "Monitor for anomalous DNS changes and unauthorized domain transfers"],  # Proactive threat hunting steps
        "expected_outcomes": ["Detection of website defacement attempts", "Identification of compromised web server credentials and unauthorized access"],  # Expected outcomes
        "false_positive": "Routine website maintenance and legitimate administrative changes may trigger alerts. Verify changes before taking action.",  # Known false positives
        "clearing_steps": ["Restore defaced websites from clean backups, change all compromised credentials, and apply patches for known vulnerabilities.", "Conduct forensic analysis to identify the source of compromise and prevent recurrence."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
