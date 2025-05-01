def get_content():
    return {
        "id": "G1012",
        "url_id": "CURIUM",
        "title": "CURIUM",
        "tags": ["iranian", "state-sponsored", "middle-east", "persistent", "social-engineering"],
        "description": "CURIUM is an Iranian threat group, first reported in September 2019 and active since at least July 2018, primarily targeting IT service providers in the Middle East. The group is known for its patient and persistent social engineering tactics, engaging targets through social media for months before delivering malware.",
        "associated_groups": ["Crimson Sandstorm", "TA456", "Tortoise Shell", "Yellow Liderc"],
        "campaigns": [],
        "techniques": [
            "T1583.001", "T1583.003", "T1583.004", "T1059.001", "T1584.006",
            "T1005", "T1189", "T1585.001", "T1585.002", "T1048.002", "T1041",
            "T1566.001", "T1566.003", "T1598.003", "T1505.003", "T1608.004",
            "T1082", "T1124", "T1204.002"
        ],
        "contributors": ["Denise Tan", "Wirapong Petshagun"],
        "version": "3.0",
        "created": "13 January 2023",
        "last_modified": "02 October 2024",
        "navigator": "",
        "references": [
            {"source": "Symantec Threat Hunter Team", "url": "https://www.symantec.com/blogs/threat-intelligence/tortoiseshell-it-providers-saudi-arabia"},
            {"source": "MSTIC", "url": "https://www.microsoft.com/security/blog/2021/11/16/evolving-trends-in-iranian-threat-actor-activity-mstic-cyberwarcon-2021"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/security/blog/2023/07/12/how-microsoft-names-threat-actors"},
            {"source": "Miller, J. et al.", "url": "https://www.proofpoint.com/us/blog/threat-insight/ta456-targets-defense-contractor-social-media-persona"},
            {"source": "PwC Threat Intelligence", "url": "https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/imaploader-malware-yellow-liderc.html"}
        ],
        "resources": ["IMAPLoader analysis", "MITRE ATT&CK Group entry"],
        "remediation": "Block known malicious infrastructure, monitor for anomalous social media interactions, and educate staff on targeted phishing tactics. Monitor and restrict use of PowerShell and external email protocols like IMAP and SMTPS.",
        "improvements": "Enhance detection for strategic website compromise attempts, monitor account creation on social media, and implement anomaly-based detection for long-term social engineering activity.",
        "hunt_steps": [
            "Search for PowerShell execution events (Sysmon Event ID 1) with suspicious command lines.",
            "Detect account creations on social media or email services using internal network logs.",
            "Identify exfiltration over SMTPS or IMAP protocols.",
            "Trace user interaction with suspicious links or attachments originating from social media."
        ],
        "expected_outcomes": [
            "Identification of compromised endpoints communicating via SMTPS.",
            "Detection of IMAPLoader payload activity.",
            "Correlation of social engineering leads to malware deployment."
        ],
        "false_positive": "Legitimate PowerShell use or email transfers over SMTPS may be flagged. Validate against known good behavior baselines.",
        "clearing_steps": [
            "Revoke access tokens or credentials obtained by adversary.",
            "Reimage or clean affected systems.",
            "Monitor and block adversary infrastructure.",
            "Conduct user awareness training for targeted personnel."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
