#dj wip
def get_content():
    return {
        "id": "Agrius",  # APT name
        "url_id": "agrius",  # URL segment APT name all lowercase with _ for spaces
        "title": "Agrius",  # Name of the APT group
        "tags": ["state-sponsored", "Iranian", "cyber espionage", "wiper malware"],  # Tags associated with the group
        "description": "Agrius is an Iranian state-sponsored cyber espionage group known for its focus on destructive operations. The group has been linked to wiper malware campaigns targeting organizations primarily in the Middle East, often masquerading as ransomware attacks.",  # Overview/description of the APT group
        "associated_groups": ["MuddyWater", "APT33"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0123",  # Campaign ID
                "name": "Desert Sting",  # Campaign name
                "first_seen": "2020",  # First seen date
                "last_seen": "2023",  # Last seen date
                "references": [
                    "https://attack.mitre.org/groups/G0126/",
                    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-201a"
                ]  # List of references
            }
        ],
        "techniques": ["T1562", "T1490", "T1059", "T1566", "T1071"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "Check Point", "CISA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "5 December 2023",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0126/"},
            {"source": "CISA", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-201a"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0126/", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-201a"],  # Additional resources
        "remediation": "Strengthen endpoint security, implement network segmentation, and maintain regular offline backups to mitigate wiper malware impact.",  # Recommended actions to mitigate risks
        "improvements": "Deploy behavioral-based detection systems, enhance logging and monitoring, and enforce strict privilege management policies.",  # Suggestions for detection and response
        "hunt_steps": ["Monitor for unauthorized file deletions and encryption attempts", "Analyze network traffic for communications with known malicious command-and-control (C2) infrastructure"],  # Proactive threat hunting steps
        "expected_outcomes": ["Early detection of wiper malware activity", "Identification of unauthorized system modifications and privilege escalation"],  # Expected outcomes
        "false_positive": "Some legitimate administrative tools may perform mass file deletions or encryption. Verify intent and origin before acting.",  # Known false positives
        "clearing_steps": ["Isolate infected systems, restore from clean backups, and block identified malicious IPs and domains.", "Perform forensic analysis to determine the extent of the attack and prevent recurrence."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
