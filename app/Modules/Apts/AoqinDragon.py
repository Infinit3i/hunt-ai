#dj wip
def get_content():
    return {
        "id": "Aoqin Dragon",  # APT name
        "url_id": "aoqin_dragon",  # URL segment APT name all lowercase with _ for spaces
        "title": "Aoqin Dragon",  # Name of the APT group
        "tags": ["state-sponsored", "Chinese", "cyber espionage"],  # Tags associated with the group
        "description": "Aoqin Dragon is a Chinese state-sponsored cyber espionage group active since at least 2013, primarily targeting government, education, and telecommunication organizations in Southeast Asia and Australia. The group is known for using USB-based malware, phishing attacks, and exploiting vulnerabilities in widely used software.",  # Overview/description of the APT group
        "associated_groups": ["Naikon", "Mustang Panda"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0225",  # Campaign ID
                "name": "Long-Term Espionage Operations in Southeast Asia",  # Campaign name
                "first_seen": "2013",  # First seen date
                "last_seen": "2022",  # Last seen date
                "references": [
                    "https://attack.mitre.org/groups/G1007/",
                    "https://www.sentinelone.com/blog/aoqin-dragon-chinese-apt-group-undetected-for-years/"
                ]  # List of references
            }
        ],
        "techniques": ["T1203", "T1566", "T1036", "T1071", "T1090"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "SentinelOne", "CISA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "25 March 2024",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G1007/"},
            {"source": "SentinelOne", "url": "https://www.sentinelone.com/blog/aoqin-dragon-chinese-apt-group-undetected-for-years/"}
        ],
        "resources": ["https://attack.mitre.org/groups/G1007/", "https://www.sentinelone.com/blog/aoqin-dragon-chinese-apt-group-undetected-for-years/"],  # Additional resources
        "remediation": "Deploy USB device control policies, enhance phishing detection measures, and apply patches to vulnerable software to mitigate risk.",  # Recommended actions to mitigate risks
        "improvements": "Increase network monitoring for command-and-control (C2) activity, enforce multi-factor authentication (MFA), and conduct regular security awareness training.",  # Suggestions for detection and response
        "hunt_steps": ["Monitor for unauthorized USB device connections and data transfers", "Analyze DNS logs for connections to known Aoqin Dragon infrastructure"],  # Proactive threat hunting steps
        "expected_outcomes": ["Detection of espionage activities within Southeast Asian organizations", "Identification of unauthorized access and malware persistence mechanisms"],  # Expected outcomes
        "false_positive": "Legitimate remote access tools and file transfers may trigger alerts. Conduct behavior-based analysis to verify intent.",  # Known false positives
        "clearing_steps": ["Revoke compromised credentials, remove unauthorized persistence mechanisms, and block malicious C2 domains.", "Conduct a forensic review of infected systems to identify further compromise."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
