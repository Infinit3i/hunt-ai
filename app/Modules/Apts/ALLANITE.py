#dj wip
def get_content():
    return {
        "id": "ALLANITE",  # APT name
        "url_id": "allanite",  # URL segment APT name all lowercase with _ for spaces
        "title": "ALLANITE",  # Name of the APT group
        "tags": ["state-sponsored", "Russian", "cyber espionage", "critical infrastructure"],  # Tags associated with the group
        "description": "ALLANITE is a Russian state-sponsored cyber espionage group known for targeting critical infrastructure, particularly in the energy sector. The group has been linked to reconnaissance and data collection activities, with some overlaps with other Russian APT groups.",  # Overview/description of the APT group
        "associated_groups": ["Dragonfly", "Berserk Bear"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0195",  # Campaign ID
                "name": "Energy Sector Reconnaissance",  # Campaign name
                "first_seen": "2017",  # First seen date
                "last_seen": "2023",  # Last seen date
                "references": [
                    "https://attack.mitre.org/groups/G1002/",
                    "https://www.dragos.com/threat-groups/allanite/"
                ]  # List of references
            }
        ],
        "techniques": ["T1071", "T1003", "T1059", "T1078", "T1210"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "Dragos", "CISA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "18 March 2024",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G1002/"},
            {"source": "Dragos", "url": "https://www.dragos.com/threat-groups/allanite/"}
        ],
        "resources": ["https://attack.mitre.org/groups/G1002/", "https://www.dragos.com/threat-groups/allanite/"],  # Additional resources
        "remediation": "Enhance industrial control system (ICS) monitoring, implement strict network segmentation, and deploy advanced intrusion detection systems (IDS).",  # Recommended actions to mitigate risks
        "improvements": "Increase logging and monitoring for ICS/SCADA environments, conduct regular threat-hunting activities, and train personnel on operational technology (OT) security risks.",  # Suggestions for detection and response
        "hunt_steps": ["Monitor ICS network traffic for anomalies", "Investigate unauthorized access attempts to critical infrastructure control systems"],  # Proactive threat hunting steps
        "expected_outcomes": ["Early detection of espionage activities in energy sector networks", "Identification of unauthorized access attempts and data exfiltration"],  # Expected outcomes
        "false_positive": "Routine remote maintenance and legitimate remote access tools used in ICS environments may generate alerts. Validate access patterns.",  # Known false positives
        "clearing_steps": ["Revoke compromised credentials, block unauthorized IP addresses, and conduct a forensic analysis of ICS logs.", "Implement additional security controls on critical infrastructure systems to prevent future intrusions."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
