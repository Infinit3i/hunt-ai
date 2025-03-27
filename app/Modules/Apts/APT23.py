#dj wip
# APT23 work in progress
def get_content():
    return {
        "id": "APT23",  # APT name
        "url_id": "apt23",  # URL segment APT name all lowercase with _ for spaces
        "title": "APT23",  # Name of the APT group
        "tags": ["state-sponsored", "Chinese", "cyber espionage"],  # Tags associated with the group
        "description": "APT23, also known as Iron Tiger, is a Chinese state-sponsored cyber espionage group known for targeting defense, telecommunications, and technology industries. The group is recognized for its sophisticated use of backdoors, custom malware, and persistent attacks against high-value targets.",  # Overview/description of the APT group
        "associated_groups": ["APT10", "APT41"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0063",  # Campaign ID
                "name": "Iron Tiger Espionage Campaigns",  # Campaign name
                "first_seen": "2015",  # First seen date
                "last_seen": "2024",  # Last seen date
                "references": ["https://attack.mitre.org/groups/G0093/", "https://www.trendmicro.com/en_us/research/21/k/iron-tiger-apt-group-updates-toolset-targets-cloud.html"]  # List of references
            }
        ],
        "techniques": ["T1566", "T1105", "T1071", "T1059", "T1210"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "Trend Micro", "CISA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "10 October 2023",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0093/"},
            {"source": "Trend Micro", "url": "https://www.trendmicro.com/en_us/research/21/k/iron-tiger-apt-group-updates-toolset-targets-cloud.html"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0093/", "https://www.trendmicro.com/en_us/research/21/k/iron-tiger-apt-group-updates-toolset-targets-cloud.html"],  # Additional resources
        "remediation": "Implement strict access controls, deploy network segmentation, and monitor for suspicious activities. Regularly update software and enforce endpoint security best practices.",  # Recommended actions to mitigate risks
        "improvements": "Enhance detection capabilities for abnormal cloud activity, conduct advanced threat hunting, and improve incident response procedures.",  # Suggestions for detection and response
        "hunt_steps": ["Monitor for unusual remote access attempts", "Detect exfiltration of sensitive data via cloud services"],  # Proactive threat hunting steps
        "expected_outcomes": ["Early detection of unauthorized access", "Mitigation of cloud-based data exfiltration"],  # Expected outcomes
        "false_positive": "Legitimate cloud storage and remote access tools may trigger alerts. Verify anomalies with behavioral analytics.",  # Known false positives
        "clearing_steps": ["Reset compromised credentials, investigate system logs for unauthorized activity, and remove persistence mechanisms.", "Improve cloud security configurations and implement advanced threat detection solutions."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
