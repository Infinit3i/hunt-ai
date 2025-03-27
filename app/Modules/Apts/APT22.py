#dj wip
# APT22 work in progress
def get_content():
    return {
        "id": "APT22",  # APT name
        "url_id": "apt22",  # URL segment APT name all lowercase with _ for spaces
        "title": "APT22",  # Name of the APT group
        "tags": ["state-sponsored", "Chinese", "cyber espionage"],  # Tags associated with the group
        "description": "APT22, also known as Barbarian Panda, is a Chinese state-sponsored cyber espionage group known for targeting political entities, human rights organizations, and research institutions. The group is highly skilled in using custom malware and conducting long-term reconnaissance on victims.",  # Overview/description of the APT group
        "associated_groups": ["APT10", "APT12"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0051",  # Campaign ID
                "name": "Barbarian Panda Operations",  # Campaign name
                "first_seen": "2016",  # First seen date
                "last_seen": "2024",  # Last seen date
                "references": ["https://attack.mitre.org/groups/G0029/", "https://www.fireeye.com/blog/threat-research/2016/10/china-based-espionage-apt22.html"]  # List of references
            }
        ],
        "techniques": ["T1566", "T1105", "T1071", "T1203", "T1036"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "FireEye", "Microsoft"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "25 September 2023",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0029/"},
            {"source": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/2016/10/china-based-espionage-apt22.html"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0029/", "https://www.fireeye.com/blog/threat-research/2016/10/china-based-espionage-apt22.html"],  # Additional resources
        "remediation": "Enhance threat intelligence gathering, deploy endpoint detection and response (EDR) solutions, and conduct regular security audits. Implement strong email security policies.",  # Recommended actions to mitigate risks
        "improvements": "Increase monitoring for stealthy malware deployment, conduct proactive threat assessments, and strengthen data encryption strategies.",  # Suggestions for detection and response
        "hunt_steps": ["Monitor for phishing attempts targeting political organizations", "Detect anomalies in network traffic indicating exfiltration"],  # Proactive threat hunting steps
        "expected_outcomes": ["Identification of stealthy malware infections", "Prevention of unauthorized data leaks"],  # Expected outcomes
        "false_positive": "Legitimate secure communications may sometimes trigger alerts. Verify suspicious activity based on behavior analytics.",  # Known false positives
        "clearing_steps": ["Revoke compromised credentials, review security logs for unusual patterns, and remove any unauthorized persistence mechanisms.", "Strengthen network segmentation to limit lateral movement."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
