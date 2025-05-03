def get_content():
    return {
        "id": "G0094",
        "url_id": "Kimsuky",
        "title": "Kimsuky",
        "tags": ["state-sponsored", "North Korea", "espionage", "nuclear policy", "AI abuse"],
        "description": (
            "Kimsuky is a North Korean cyber espionage group active since at least 2012. "
            "Initially targeting South Korean government entities and think tanks, the group expanded operations to the US, Japan, Russia, and Europe. "
            "It focuses on intelligence gathering related to Korean peninsula policy, sanctions, and nuclear issues. "
            "Kimsuky is known for spearphishing, abuse of commercial LLMs for research and reconnaissance, and overlapping operations with other DPRK clusters. "
            "Notable incidents include Operation STOLEN PENCIL (2018), Operation Kabar Cobra (2019), and the 2014 Korea Hydro & Nuclear Power Co. breach."
        ),
        "associated_groups": [
            "Black Banshee", "Velvet Chollima", "Emerald Sleet", "THALLIUM", "APT43", "TA427", "Springtail"
        ],
        "campaigns": [
            {
                "id": "C0001",
                "name": "Operation STOLEN PENCIL",
                "first_seen": "2018",
                "last_seen": "2018",
                "references": ["https://asert.arbornetworks.com/stolen-pencil-campaign-targets-academia/"]
            },
            {
                "id": "C0002",
                "name": "Operation Kabar Cobra",
                "first_seen": "2019",
                "last_seen": "2019",
                "references": ["https://www.ahnlab.com"]
            },
            {
                "id": "C0003",
                "name": "Operation Smoke Screen",
                "first_seen": "2019",
                "last_seen": "2019",
                "references": ["https://blog.alyac.co.kr/2243"]
            }
        ],
        "techniques": [
            "T1059.001", "T1059.003", "T1059.005", "T1059.006", "T1059.007", "T1053.005", "T1204.001", "T1204.002",
            "T1056.001", "T1113", "T1027", "T1583.001", "T1583.004", "T1583.006", "T1566.001", "T1566.002",
            "T1585.001", "T1585.002", "T1083", "T1016", "T1082", "T1005", "T1555.003", "T1547.001", "T1105", "T1140",
            "T1003.001", "T1552.001", "T1560.001", "T1560.003", "T1543.003", "T1112", "T1036.004", "T1036.005",
            "T1218.005", "T1218.010", "T1218.011", "T1219.002", "T1114.002", "T1114.003", "T1102.001", "T1102.002",
            "T1593", "T1593.001", "T1593.002", "T1596", "T1598", "T1598.003", "T1586.002", "T1584.001", "T1021.001",
            "T1534", "T1055", "T1055.012", "T1620", "T1553.002", "T1087.007", "T1012", "T1007", "T1016", "T1041",
            "T1567.002", "T1657", "T1562.001", "T1562.004", "T1070.004", "T1070.006", "T1518.001", "T1176.001",
            "T1608.001", "T1539", "T1656"
        ],
        "contributors": [
            "Taewoo Lee, KISA", "Dongwook Kim, KISA", "Jaesang Oh, KC7 Foundation"
        ],
        "version": "5.1",
        "created": "26 August 2019",
        "last_modified": "29 January 2025",
        "navigator": "https://attack.mitre.org/groups/G0094/",
        "references": [
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0094/"},
            {"source": "Mandiant", "url": "https://www.mandiant.com/resources/apt43-funding-espionage"},
            {"source": "Microsoft Threat Intelligence", "url": "https://www.microsoft.com/security/blog/2024/02/14/staying-ahead-of-threat-actors-in-the-age-of-ai/"}
        ],
        "resources": [
            "https://us-cert.cisa.gov/ncas/alerts/aa20-301a",
            "https://www.ahnlab.com",
            "https://blog.alyac.co.kr/2243"
        ],
        "remediation": (
            "Implement network segmentation, limit the use of RDP, enforce MFA for all remote access, "
            "block known malicious infrastructure, deploy EDR and behavior-based detection systems, "
            "and monitor email for spearphishing indicators."
        ),
        "improvements": (
            "Enhance detection of PowerShell and VBScript abuse, inspect email forwarding rules, "
            "validate file integrity on startup items, and monitor use of legitimate system binaries for proxy execution."
        ),
        "hunt_steps": [
            "Search for abnormal use of mshta.exe, regsvr32.exe, and rundll32.exe",
            "Check for recent user account creations via 'net user'",
            "Look for HTTP POSTs to Blogspot or GitHub used as C2",
            "Inspect PowerShell logs for reflective DLL loads or encoded commands"
        ],
        "expected_outcomes": [
            "Detection of persistence via startup folder or registry run keys",
            "Identification of lateral movement using RDP with new local accounts",
            "Uncover use of credentials stolen via browser harvesting",
            "Discovery of staged exfiltration paths under Ole DB directory"
        ],
        "false_positive": (
            "Use of mshta.exe, PowerShell, and scheduled tasks may be legitimate in enterprise environments. "
            "Contextualize with user behavior and frequency to minimize false alerts."
        ),
        "clearing_steps": [
            "Disable compromised accounts and reset credentials",
            "Remove persistence artifacts from startup folders and Registry",
            "Delete exfiltrated staging directories",
            "Review and clean up scheduled tasks created by threat actor"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://blog.alyac.co.kr/2243",
                "https://www.microsoft.com/security/blog/2024/02/14/staying-ahead-of-threat-actors-in-the-age-of-ai/"
            ]
        }
    }
