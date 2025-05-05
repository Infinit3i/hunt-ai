def get_content():
    return {
        "id": "G0049",
        "url_id": "OilRig",
        "title": "OilRig",
        "tags": ["APT34", "Iranian", "Middle East", "supply-chain", "government", "espionage", "OilRig-campaigns"],
        "description": (
            "OilRig is a suspected Iranian state-sponsored threat group active since at least 2014. It has targeted a variety of sectors globally, "
            "with a focus on Middle Eastern organizations across government, energy, chemical, financial, and telecommunications industries. "
            "OilRig is known for supply chain attacks and using social engineering techniques such as spearphishing. "
            "Attribution to the Iranian government is supported by infrastructure ties and geopolitical targeting patterns."
        ),
        "associated_groups": [
            "COBALT GYPSY", "IRN2", "APT34", "Helix Kitten", "Evasive Serpens", "Hazel Sandstorm",
            "EUROPIUM", "ITG13", "Earth Simnavaz", "Crambus", "TA452"
        ],
        "campaigns": [
            {
                "id": "C0044",
                "name": "Juicy Mix",
                "first_seen": "January 2022",
                "last_seen": "December 2022",
                "references": [
                    "https://www.welivesecurity.com/2023/09/21/oilrig-juicy-mix-analysis"
                ]
            },
            {
                "id": "C0042",
                "name": "Outer Space",
                "first_seen": "January 2021",
                "last_seen": "December 2021",
                "references": [
                    "https://www.welivesecurity.com/2023/09/21/oilrig-outer-space-analysis"
                ]
            }
        ],
        "techniques": [
            "T1059.001", "T1059.003", "T1059.005", "T1203", "T1068", "T1005", "T1087.001", "T1087.002", "T1110",
            "T1566.001", "T1566.002", "T1566.003", "T1105", "T1053.005", "T1217", "T1025", "T1046", "T1027.005",
            "T1027.013", "T1555.003", "T1555.004", "T1555", "T1082", "T1016", "T1049", "T1033", "T1007", "T1113",
            "T1057", "T1140", "T1573.002", "T1586.002", "T1583.001", "T1584.004", "T1585.003", "T1587.001",
            "T1588.002", "T1588.003", "T1133", "T1195", "T1505.003", "T1552.001", "T1553.002", "T1556.002",
            "T1219", "T1218.001", "T1137.004", "T1047", "T1012", "T1036", "T1036.005", "T1112", "T1070.004",
            "T1056.001", "T1204.001", "T1204.002", "T1078", "T1078.002", "T1497.001", "T1120", "T1069.001",
            "T1069.002", "T1132.001", "T1218", "T1572", "T1608.001"
        ],
        "contributors": [
            "Robert Falcone", "Bryan Lee", "Dragos Threat Intelligence", "Jaesang Oh, KC7 Foundation"
        ],
        "version": "5.0",
        "created": "14 December 2017",
        "last_modified": "16 January 2025",
        "navigator": "",
        "references": [
            {"source": "Unit42", "url": "https://unit42.paloaltonetworks.com/oilrig"},
            {"source": "ClearSky", "url": "https://www.clearskysec.com/oilrig/"},
            {"source": "Symantec", "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/oilrig-middle-east"},
            {"source": "Welivesecurity", "url": "https://www.welivesecurity.com/tag/oilrig/"},
            {"source": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html"}
        ],
        "resources": [],
        "remediation": (
            "Enforce email filtering and anti-phishing protections. "
            "Restrict PowerShell and VBScript usage where possible. "
            "Implement application whitelisting and regularly audit credential usage and RDP access. "
            "Monitor for suspicious use of scheduled tasks, Windows Management Instrumentation (WMI), and credential dumping tools like LaZagne and Mimikatz."
        ),
        "improvements": (
            "Deploy anomaly detection on Office macro usage, track downloads from remote URLs via scripts, "
            "and use behavioral analytics to catch living-off-the-land techniques (LOTL) such as use of certutil, reg.exe, and schtasks."
        ),
        "hunt_steps": [
            "Look for PowerShell execution with encoded commands.",
            "Search logs for usage of LaZagne, Mimikatz, or credential access to web browsers and Windows Credential Manager.",
            "Audit DNS and HTTP traffic to detect covert C2 over common ports.",
            "Flag suspicious task creation or system service installations tied to unexpected scripts."
        ],
        "expected_outcomes": [
            "Detection of credential dumping or browser data theft.",
            "Attribution of staged malware families such as Mango, Solar, or BONDUPDATER to OilRig.",
            "Mitigation of persistent access methods like scheduled tasks and web shells."
        ],
        "false_positive": (
            "Some LOTL techniques (e.g., PowerShell or certutil usage) are common in enterprise environments. "
            "Baseline normal admin activity and prioritize alerts based on context and timing."
        ),
        "clearing_steps": [
            "Disable malicious scheduled tasks and services.",
            "Delete files staged in TEMP or disguised as Adobe, Chrome, etc.",
            "Invalidate all harvested credentials, focusing on domain and cloud accounts."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
