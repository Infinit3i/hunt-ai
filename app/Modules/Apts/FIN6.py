def get_content():
    return {
        "id": "G0037",
        "url_id": "FIN6",
        "title": "FIN6",
        "tags": ["cybercrime", "financial theft", "point-of-sale", "ecommerce"],
        "description": "FIN6 is a financially motivated cyber crime group that has stolen payment card data and sold it on underground marketplaces. It has aggressively targeted point-of-sale systems in the hospitality and retail sectors, and has also adapted to target e-commerce platforms.",
        "associated_groups": ["Magecart Group 6", "ITG08", "Skeleton Spider", "TAAL", "Camouflage Tempest"],
        "campaigns": [],
        "techniques": [
            "T1134", "T1087.002", "T1560", "T1560.003", "T1119", "T1547.001", "T1110.002",
            "T1059", "T1059.001", "T1059.003", "T1059.007", "T1555", "T1555.003", "T1213",
            "T1005", "T1074.002", "T1573.002", "T1048.003", "T1068", "T1562.001", "T1070.004",
            "T1036.004", "T1046", "T1095", "T1027.010", "T1588.002", "T1003.001", "T1003.003",
            "T1566.001", "T1566.003", "T1572", "T1021.001", "T1018", "T1053.005", "T1553.002",
            "T1569.002", "T1204.002", "T1078", "T1102", "T1047"
        ],
        "contributors": ["Center for Threat-Informed Defense (CTID)", "Drew Church, Splunk"],
        "version": "4.0",
        "created": "31 May 2017",
        "last_modified": "17 November 2024",
        "navigator": "",  # You may insert the ATT&CK Navigator URL if applicable
        "references": [
            {"source": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/2016/04/follow-the-money-fin6.html"},
            {"source": "McKeague et al.", "url": "https://www.fireeye.com/blog/threat-research/2019/04/intercepting-a-fin6-intrusion.html"},
            {"source": "Villadsen, O.", "url": "https://www.proofpoint.com/us/blog/threat-insight/itg08-aka-fin6-partners-trickbot-gang-uses-anchor-framework"},
            {"source": "CrowdStrike", "url": "https://www.crowdstrike.com/resources/reports/global-threat-report-2018/"},
            {"source": "Visa Public", "url": "https://usa.visa.com/dam/VCOM/download/merchants/visa-threat-intelligence-fin6.pdf"},
        ],
        "resources": [],
        "remediation": "Segment POS networks, restrict PowerShell usage, enforce strong password policies, use application whitelisting, monitor egress traffic, and deploy multi-factor authentication.",
        "improvements": "Enhance detection of scheduled tasks, encoded PowerShell commands, unusual RDP usage, and cross-reference tools like AdFind and Mimikatz with threat intelligence feeds.",
        "hunt_steps": [
            "Look for abnormal ZIP or Base64 file activity in POS environments.",
            "Search for encoded PowerShell execution from unexpected accounts.",
            "Detect kill.bat or similar scripts used for disabling AV tools."
        ],
        "expected_outcomes": [
            "Identify persistence via Run keys or scheduled tasks.",
            "Uncover C2 activity using Plink SSH tunnels.",
            "Detect staged payment card data exfiltrated via HTTP POST."
        ],
        "false_positive": "Encoded PowerShell may be used legitimately in automation scripts—review in context of user account and origin.",
        "clearing_steps": [
            "Terminate unauthorized RDP and SSH sessions.",
            "Delete scheduled tasks created by FIN6 malware (e.g., FrameworkPOS).",
            "Remove files created or manipulated by kill.bat or other tools.",
            "Reset passwords for all compromised accounts."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
