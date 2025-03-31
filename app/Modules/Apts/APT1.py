# bartholomew
def get_content():
    return {
        "id": "APT1",  # APT name
        "url_id": "apt1",  # URL segment APT name all lowercase with _ for spaces
        "title": "APT1 (Comment Panda)",  # Name of the APT group
        "tags": ["state-sponsored", "Chinese", "cyber espionage", "Unit 61398"],  # Tags associated with the group
        "description": "APT1, also known as Comment Panda, is a Chinese threat group that has been attributed to the 2nd Bureau of the People’s Liberation Army (PLA) General Staff Department’s (GSD) 3rd Department, commonly known by its Military Unit Cover Designator (MUCD) as Unit 61398.",  # Overview/description of the APT group
        "associated_groups": ["Comment Crew, Comment Group"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "N/A",  # Campaign ID
                "name": "",  # Campaign name
                "first_seen": "",  # First seen date
                "last_seen": "",  # Last seen date
                "references": [
                    "https://attack.mitre.org/groups/G0006/",
                    ""
                ]  # List of references
            }
        ],
        "techniques": ["T1059", "T1119", "T1560", "T1583", "T1087", "T1584", "T1005", "T1114", "T1585", "T1036", "T1135", "T1588", "T1003", "T1566", "T1057", "T1021", "T1016", "T1049", "T1007", "T1550"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "FireEye", "Madiant", "Crowdstrike"],  # Contributors of the intel
        "version": "1.4",  # Version of this APT entry
        "created": "31 May 2017",  # Date when this entry was created
        "last_modified": "26 May 2021",  # Date when this entry was last modified
        "navigator": "https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2FG0006%2FG0006-enterprise-layer.json",
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0006/"},
            {"source": "Madiant", "url": "https://cloud.google.com/blog/topics/threat-intelligence/mandiant-exposes-apt1-chinas-cyber-espionage-units"},
            {"source": "FireEye", "url": "https://cdn0.vox-cdn.com/assets/4589853/crowdstrike-intelligence-report-putter-panda.original.pdf"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0006/", "https://cloud.google.com/blog/topics/threat-intelligence/mandiant-exposes-apt1-chinas-cyber-espionage-units"],  # Additional resources
        "remediation": "Strengthen email security and user awareness, Enforce strong access controls, monitor and restrict Lateral Movement.",  # Recommended actions to mitigate risks
        "improvements": "Robust Endpoint and Network Monitoring, Swift containment, and continuous threat hunting",  # Suggestions for detection and response
        "hunt_steps": ["Create a hypothesis that alligns with APT1's TTP's", "Identify data sources == Endpoints, Network traffic, Active Directory, E/Mail Gateway logs"],  # Proactive threat hunting steps
        "expected_outcomes": ["Compromised User Accounts and Systems through Phishing", "Identification of lateral movement within the network via PsExec, Powershell, etc"],  # Expected outcomes
        "false_positive": "Legitimate use of Windows Utilities, Large Data Transfers, Macro Enabled Documents",  # Known false positives
        "clearing_steps": ["Identify and Cotain Infected Systems, Eradicate the Adversary and attempt to Validate and Recover"],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
