def get_content():
    return {
        "id": "APT28",  # APT name
        "url_id": "apt28",  # URL segment APT name all lowercase with _ for spaces
        "title": "APT28",  # Name of the APT group (e.g., "APT28")
        "tags": ["state-sponsored", "Russian", "cyber espionage"],  # Tags associated with the group
        "description": "APT28, also known as Fancy Bear, is a Russian cyber espionage group associated with the Russian government. The group primarily targets government, military, and media organizations in NATO countries and Eastern Europe. APT28 has been linked to high-profile attacks, including the hack of the Democratic National Committee (DNC) in 2016.",  # Overview/description of the APT group
        "associated_groups": ["Sofacy", "Sednit"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0011",  # Campaign ID
                "name": "Sofacy Campaign",  # Campaign name
                "first_seen": "2014",  # First seen date
                "last_seen": "2021",  # Last seen date
                "references": ["https://www.cybereason.com/blog/apt28", "https://www.fireeye.com/blog/threat-research/2020/06/fancy-bear-disk-to-ram-malware.html"]  # List of references or URLs for the campaign details
            }
        ],
        "techniques": ["T1071", "T1086", "T1027", "T1213", "T1070"],  # List of techniques employed by this APT group
        "contributors": ["FireEye", "CrowdStrike", "US-CERT"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "20 May 2023",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/2020/06/fancy-bear-disk-to-ram-malware.html"},
            {"source": "CrowdStrike", "url": "https://www.crowdstrike.com/blog/the-apt28-anatomy-of-a-cyber-espionage-actor/"}
        ],
        "resources": ["https://www.cybereason.com/blog/apt28", "https://www.fireeye.com/blog/threat-research/2020/06/fancy-bear-disk-to-ram-malware.html"],  # Additional resources
        "remediation": "Implement network segmentation, deploy endpoint protection tools, and ensure timely patching of critical vulnerabilities. Monitor for indicators of compromise (IOCs) related to this group.",  # Recommended actions to mitigate risks posed by this APT
        "improvements": "Enhance email filtering to prevent spear-phishing attacks, implement multi-factor authentication (MFA) where possible, and improve overall awareness of social engineering techniques.",  # Suggestions for enhancing detection and response
        "hunt_steps": ["Monitor for suspicious network traffic to known APT28 IP ranges", "Check for the use of malicious PowerShell scripts on endpoints"],  # Proactive threat hunting steps
        "expected_outcomes": ["Discovery of known IOCs in network traffic or endpoint logs", "Identification of malware artifacts or unauthorized remote access"],  # Expected outcomes
        "false_positive": "False positives may occur due to legitimate use of certain IP addresses or domains commonly used by APT28, such as those used for email infrastructure. Create rules to validate the context of these occurrences.",  # Known false positives and guidance
        "clearing_steps": ["Use antivirus software to remove malware, manually inspect affected systems for persistence mechanisms, and ensure that all backdoors have been closed.", "Review network traffic logs to identify and remove any other backdoors or command-and-control channels."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": ["12c6d378a4c66b3b44b90d91f68b9fa282b9fce9d99d073a33fa63a539b104e9"],  # Example SHA256 hash value
            "md5": ["f7d93f8d6a1c6b7fc54d6cfcc598a13d"],  # Example MD5 hash value
            "ip": ["185.215.232.33", "5.189.133.50"],  # Example IP addresses
            "domain": ["fancybear.ru", "apt28.com"],  # Example domains
            "resources": ["https://www.fireeye.com/blog/threat-research/2020/06/fancy-bear-disk-to-ram-malware.html"]  # Additional resources or references for IOCs if applicable
        }
    }
