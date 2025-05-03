def get_content():
    return {
        "id": "G1001",
        "url_id": "HEXANE",
        "title": "HEXANE",
        "tags": ["Iran", "Middle East", "espionage", "Lyceum", "Siamesekitten", "Spirlin", "HomeLand Justice", "oil & gas", "telecom"],
        "description": "HEXANE is a cyber espionage group active since at least 2017, primarily targeting oil & gas, telecom, aviation, and ISP sectors in the Middle East and Africa. Their tactics are similar to APT33 and OilRig, but HEXANE uses distinct victim targeting and tooling. They have leveraged credential harvesting, RDP access, spearphishing, data exfiltration to cloud storage, ransomware (ROADSWEEP), and disk wipers (ZeroCleare) as part of disruptive campaigns like HomeLand Justice.",
        "associated_groups": ["Lyceum", "Siamesekitten", "Spirlin"],
        "campaigns": ["HomeLand Justice"],
        "techniques": [
            "T1134.001", "T1087.003", "T1098.002", "T1583.001", "T1583.002", "T1010", "T1110", "T1110.003",
            "T1059.001", "T1059.003", "T1059.005", "T1586.002", "T1555", "T1555.003", "T1486", "T1561.002",
            "T1114.002", "T1585.001", "T1585.002", "T1546.003", "T1041", "T1567.002", "T1190", "T1589", "T1589.002",
            "T1591.004", "T1562.001", "T1562.002", "T1105", "T1056.001", "T1534", "T1570", "T1036.005", "T1046",
            "T1027.010", "T1588.002", "T1588.003", "T1003.001", "T1069.001", "T1057", "T1021.001", "T1021.002",
            "T1018", "T1053.005", "T1505.003", "T1518", "T1608.001", "T1082", "T1016", "T1016.001", "T1049",
            "T1033", "T1204.002", "T1078.001", "T1102.002", "T1047"
        ],
        "contributors": ["Dragos Threat Intelligence", "Mindaugas Gudzis, BT Security"],
        "version": "2.3",
        "created": "17 October 2018",
        "last_modified": "14 August 2024",
        "navigator": "",
        "references": [
            {"source": "Dragos", "url": "https://www.dragos.com"},
            {"source": "ClearSky", "url": "https://www.clearskysec.com"},
            {"source": "Accenture", "url": "https://www.accenture.com"},
            {"source": "CISA Alert AA22-264A", "url": "https://www.cisa.gov/news-events/alerts/aa22-264a"}
        ],
        "resources": [],
        "remediation": "Patch externally facing apps, monitor for .aspx webshells, audit use of impersonation rights and mailbox delegation, disable default admin accounts, and isolate systems using ZeroCleare/ROADSWEEP indicators.",
        "improvements": "Increase logging retention, monitor cloud storage uploads, alert on encoded PowerShell and cmdkey usage, and review WMI persistence.",
        "hunt_steps": [
            "Detect ROADSWEEP and ZeroCleare file names (e.g., GoXML.exe, cl.exe).",
            "Inspect Exchange logs for abnormal mailbox access or impersonation.",
            "Search for Base64 encoded PowerShell scripts or kl.ps1."
        ],
        "expected_outcomes": [
            "Identification of WMI persistence and impersonation abuse.",
            "Detection of lateral movement via RDP and SMB shares.",
            "Prevention of data exfiltration via OneDrive or ProtonMail."
        ],
        "false_positive": "Legitimate use of PowerShell cmdlets for mailbox search and remote admin actions may appear similar; correlation with behavioral context is necessary.",
        "clearing_steps": [
            "Remove scheduled tasks created by malware.",
            "Delete .aspx backdoors and persistence scripts.",
            "Revoke stolen email delegation rights.",
            "Reset credentials and delete default admin accounts."],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }