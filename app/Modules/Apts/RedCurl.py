def get_content():
    return {
        "id": "G1039",
        "url_id": "RedCurl",
        "title": "RedCurl",
        "tags": ["espionage", "russia", "corporate-targeting", "cloud-exfiltration", "redteam-like"],
        "description": (
            "RedCurl is a Russian-speaking cyber espionage group active since 2018. It has conducted attacks against corporations across various regions, "
            "including Ukraine, Canada, the United Kingdom, and Australia. Industries targeted include travel, insurance, banking, legal services, and retail. "
            "RedCurl is notable for its use of red team-like TTPs, spearphishing campaigns with malicious links or attachments, and data exfiltration via "
            "cloud storage (e.g., Mega). The group often uses tools like LaZagne and PowerShell scripts, employs masquerading and credential harvesting, and "
            "builds its own tools to evade detection and exfiltrate data discreetly."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1087.001", "T1087.002", "T1087.003", "T1071.001", "T1560.001", "T1119", "T1020", "T1547.001",
            "T1059.001", "T1059.003", "T1059.005", "T1059.006", "T1555.003", "T1005", "T1039", "T1587.001",
            "T1114.001", "T1573.001", "T1573.002", "T1083", "T1564.001", "T1070.004", "T1202", "T1056.002",
            "T1036.005", "T1046", "T1027", "T1003.001", "T1566.001", "T1566.002", "T1053.005", "T1218.011",
            "T1082", "T1080", "T1537", "T1199", "T1552.001", "T1552.002", "T1204.001", "T1204.002", "T1102"
        ],
        "contributors": ["Joe Gumke, U.S. Bank"],
        "version": "1.0",
        "created": "23 September 2024",
        "last_modified": "23 September 2024",
        "navigator": "",
        "references": [
            {"source": "Group-IB (2020)", "url": "https://group-ib.com/resources/threat-research/redcurl/"},
            {"source": "Group-IB (2021)", "url": "https://group-ib.com/blog/redcurl-awakening/"},
            {"source": "Trend Micro MDR", "url": "https://www.trendmicro.com/en_us/research/24/c/redcurl-cyberespionage.html"},
            {"source": "Antoniuk, D. (2023)", "url": "https://www.bleepingcomputer.com/news/security/redcurl-hackers-return-to-spy-on-major-russian-bank-australian-company/"}
        ],
        "resources": [],
        "remediation": (
            "Block execution of scripting engines (PowerShell, VBScript, Python) where not needed. Restrict access to cloud storage utilities "
            "like Mega unless explicitly required. Implement application control and EDR solutions to monitor credential dumping tools like LaZagne. "
            "Train users on phishing awareness and enforce MFA to mitigate credential theft."
        ),
        "improvements": (
            "Improve visibility over user-initiated scheduled tasks and registry changes. Detect misuse of built-in binaries like rundll32 and pcalua. "
            "Flag hidden LNK files and user profile-level persistence techniques. Implement network inspection for encrypted outbound traffic to unknown destinations."
        ),
        "hunt_steps": [
            "Search for recent registry changes under HKCU\\...\\Run indicating persistence.",
            "Identify scheduled tasks with suspicious or deceptive names.",
            "Look for LaZagne-related binaries or output files.",
            "Detect use of PowerShell, Python, or VBS scripts in unusual execution contexts.",
            "Search for exfiltration activity using Mega or other cloud utilities.",
            "Check for rundll32 or pcalua used with uncommon arguments."
        ],
        "expected_outcomes": [
            "Discovery of unauthorized persistence and credential theft activity.",
            "Identification of exfiltration attempts via cloud services.",
            "Uncovering of obfuscated file execution and hidden artifacts.",
            "Awareness of spearphishing lures and discovery of initial access vectors."
        ],
        "false_positive": (
            "Some usage of PowerShell, Python, or rundll32 may be legitimate. Validate against known software baselines, contextual behavior, and user roles."
        ),
        "clearing_steps": [
            "Terminate any malicious scripts and delete scheduled tasks or registry entries.",
            "Remove any cloud tools like megatools if not required.",
            "Clear local copies of collected or exfiltrated data.",
            "Audit user credentials, rotate passwords, and enforce MFA where appropriate."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
