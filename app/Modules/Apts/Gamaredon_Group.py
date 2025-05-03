def get_content():
    return {
        "id": "G0047",
        "url_id": "Gamaredon_Group",
        "title": "Gamaredon Group",
        "tags": ["state-sponsored", "Russia", "espionage", "Ukraine", "APT"],
        "description": "Gamaredon Group is a suspected Russian cyber espionage group attributed to Russia's FSB Center 18. It has been active since at least 2013, targeting Ukrainian military, NGO, law enforcement, judiciary, and non-profit organizations. The group is known for persistent spearphishing campaigns, document macro abuse, and extensive data theft.",
        "associated_groups": ["IRON TILDEN", "Primitive Bear", "ACTINIUM", "Armageddon", "Shuckworm", "DEV-0157", "Aqua Blizzard"],
        "campaigns": [],
        "techniques": [
            "T1583.001", "T1583.003", "T1071.001", "T1119", "T1020", "T1547.001", "T1059.001", "T1059.003", "T1059.005",
            "T1005", "T1039", "T1025", "T1001", "T1491.001", "T1140", "T1561.001", "T1568", "T1568.001", "T1480",
            "T1041", "T1083", "T1564.003", "T1562.001", "T1070.004", "T1105", "T1559.001", "T1534", "T1036.005",
            "T1112", "T1106", "T1027", "T1027.004", "T1027.010", "T1027.016", "T1588.002", "T1137", "T1120", "T1566.001",
            "T1057", "T1021.005", "T1053.005", "T1113", "T1608.001", "T1218.005", "T1218.011", "T1082", "T1016.001",
            "T1033", "T1080", "T1221", "T1204.001", "T1204.002", "T1102", "T1102.003", "T1047"
        ],
        "contributors": [
            "ESET", 
            "Trend Micro Incorporated", 
            "Yoshihiro Kori, NEC Corporation", 
            "Manikantan Srinivasan, NEC Corporation India", 
            "Pooja Natarajan, NEC Corporation India"
        ],
        "version": "3.1",
        "created": "31 May 2017",
        "last_modified": "23 September 2024",
        "navigator": "",  # Add MITRE Navigator link if available
        "references": [
            {"source": "ESET", "url": "https://www.welivesecurity.com/2020/06/11/gamaredon-group-grows-its-game/"},
            {"source": "Microsoft Threat Intelligence Center", "url": "https://www.microsoft.com/security/blog/2022/02/04/actinium-targets-ukrainian-organizations/"},
            {"source": "Unit 42", "url": "https://unit42.paloaltonetworks.com/russias-trident-ursa-aka-gamaredon-apt-cyber-conflict-operations/"},
            {"source": "Symantec", "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/shuckworm-cyberespionage-ukraine"},
            {"source": "CERT-EE", "url": "https://cert.ee/en/2021/01/gamaredon-infection-analysis/"}
        ],
        "resources": [],
        "remediation": "Implement strong macro controls and endpoint defenses; monitor and alert for known C2 infrastructure; enhance email filtering for spearphishing detection.",
        "improvements": "Develop behavioral detection for macro execution anomalies; monitor document template injection behaviors and registry changes.",
        "hunt_steps": [
            "Search for Word/Excel files with unexpected macro injections.",
            "Monitor scheduled tasks and registry keys related to VBScript execution.",
            "Detect abnormal HTTP/HTTPS traffic to uncommon domains or fast flux IPs.",
            "Hunt for files with hidden windows or batch file executions."
        ],
        "expected_outcomes": [
            "Identification of suspicious document templates.",
            "Detection of lateral movement via Outlook VBA or VNC tools.",
            "Discovery of C2 communications via Telegram, GitHub, or DDNS."
        ],
        "false_positive": "Some legitimate administrative scripts may resemble VBScript or PowerShell-based tactics; validate context before action.",
        "clearing_steps": [
            "Remove malicious Run keys and scheduled tasks.",
            "Delete identified malicious documents and scripts.",
            "Revert tampered Office and registry settings."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
