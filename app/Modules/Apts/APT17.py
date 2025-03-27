#dj wip
# APT17 work in progress
def get_content():
    return {
        "id": "APT17",  # APT name
        "url_id": "apt17",  # URL segment APT name all lowercase with _ for spaces
        "title": "APT17",  # Name of the APT group
        "tags": ["state-sponsored", "Chinese", "cyber espionage"],  # Tags associated with the group
        "description": "APT17, also known as DeputyDog, is a Chinese state-sponsored cyber espionage group known for targeting government entities, technology firms, and NGOs. The group is adept at leveraging zero-day exploits and conducting long-term cyber operations.",  # Overview/description of the APT group
        "associated_groups": ["APT10", "APT41"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0032",  # Campaign ID
                "name": "DeputyDog Operations",  # Campaign name
                "first_seen": "2013",  # First seen date
                "last_seen": "2019",  # Last seen date
                "references": ["https://attack.mitre.org/groups/G0025/", "https://www.fireeye.com/blog/threat-research/2013/09/deputydog-china-based-apt-targets-us-law-firms.html"]  # List of references
            }
        ],
        "techniques": ["T1060", "T1105", "T1027", "T1036", "T1190"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "FireEye", "CISA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "12 May 2023",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0025/"},
            {"source": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/2013/09/deputydog-china-based-apt-targets-us-law-firms.html"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0025/", "https://www.fireeye.com/blog/threat-research/2013/09/deputydog-china-based-apt-targets-us-law-firms.html"],  # Additional resources
        "remediation": "Employ advanced endpoint protection, restrict access to critical systems, and monitor network traffic for unauthorized communications. Regularly update software to mitigate exploits.",  # Recommended actions to mitigate risks
        "improvements": "Enhance security analytics, deploy AI-driven anomaly detection, and conduct continuous security assessments.",  # Suggestions for detection and response
        "hunt_steps": ["Monitor for abnormal data exfiltration attempts", "Identify use of obfuscated payloads in network traffic"],  # Proactive threat hunting steps
        "expected_outcomes": ["Detection of unauthorized access attempts", "Identification of malware persistence mechanisms"],  # Expected outcomes
        "false_positive": "Normal system administrative tools may generate similar activity. Analyze behavioral patterns to validate threats.",  # Known false positives
        "clearing_steps": ["Revoke compromised credentials, isolate affected hosts, and conduct forensic analysis to identify backdoors.", "Review logs and remove unauthorized scripts or tools."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
