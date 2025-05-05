def get_content():
    return {
        "id": "G0069",
        "url_id": "MuddyWater",
        "title": "MuddyWater",
        "tags": ["iran", "espionage", "credential theft", "proxy abuse", "MOIS", "APT", "seedworm", "government targeting"],
        "description": (
            "MuddyWater is an Iranian cyber espionage group assessed to operate under Iran's Ministry of Intelligence and Security (MOIS). "
            "Active since at least 2017, MuddyWater targets government and private organizations across telecommunications, energy, defense, and other sectors. "
            "Their operations span the Middle East, Asia, Africa, Europe, and North America. The group employs a wide variety of TTPs including credential dumping, "
            "custom malware, obfuscation, and the abuse of legitimate tools for persistence and remote access."
        ),
        "associated_groups": [
            "Earth Vetala", "MERCURY", "Static Kitten", "Seedworm",
            "TEMP.Zagros", "Mango Sandstorm", "TA450"
        ],
        "campaigns": [],
        "techniques": [
            "T1548.002", "T1087.002", "T1583.006", "T1071.001", "T1560.001",
            "T1547.001", "T1059.001", "T1059.003", "T1059.005", "T1059.006", "T1059.007",
            "T1555", "T1555.003", "T1132.001", "T1074.001", "T1140", "T1573.001",
            "T1041", "T1190", "T1203", "T1210", "T1083", "T1574.001", "T1562.001",
            "T1105", "T1559.001", "T1559.002", "T1036.005", "T1104", "T1027.003",
            "T1027.004", "T1027.010", "T1588.002", "T1137.001", "T1003.001", "T1003.004",
            "T1003.005", "T1566.001", "T1566.002", "T1057", "T1090.002", "T1219",
            "T1053.005", "T1113", "T1518", "T1518.001", "T1218.003", "T1218.005",
            "T1218.011", "T1082", "T1016", "T1049", "T1033", "T1552.001",
            "T1204.001", "T1204.002", "T1102.002", "T1047"
        ],
        "contributors": [
            "Ozer Sarilar, @ozersarilar, STM",
            "Daniyal Naeem, BT Security",
            "Marco Pedrinazzi, @pedrinazziM"
        ],
        "version": "5.1",
        "created": "18 April 2018",
        "last_modified": "29 August 2024",
        "navigator": "",
        "references": [
            {
                "source": "Cyber National Mission Force",
                "url": "https://www.cybercom.mil/Media/News/Article/2891938"
            },
            {
                "source": "ClearSky",
                "url": "https://www.clearskysec.com/iranian-apt-group-muddywater-adds-exploits/"
            },
            {
                "source": "Symantec",
                "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/seedworm-iran-apt"
            },
            {
                "source": "Microsoft",
                "url": "https://www.microsoft.com/security/blog/2023/07/12/how-microsoft-names-threat-actors/"
            }
        ],
        "resources": [],
        "remediation": (
            "Implement defense-in-depth across remote access points, ensure EDR visibility for PowerShell and MSHTA abuse, "
            "and apply least-privilege principles to limit escalation. Patch vulnerable Exchange and Office software promptly."
        ),
        "improvements": (
            "Deploy proxy-aware C2 detection analytics, enrich logs with command-line auditing, and implement "
            "macro-blocking policies on Office documents from untrusted sources."
        ),
        "hunt_steps": [
            "Scan for scheduled tasks referencing rundll32, PowerShell, mshta, or COM-based execution.",
            "Hunt for use of ConnectWise, ScreenConnect, or RemoteUtilities launched from user space.",
            "Correlate base64 encoded PowerShell from phishing origins with credential access or staging behavior."
        ],
        "expected_outcomes": [
            "Identification of command and control infrastructure using multi-stage or proxy techniques.",
            "Detection of staged malware such as POWERSTATS and its variants.",
            "Discovery of credential harvesting using LaZagne, Mimikatz, and browser-based password scraping."
        ],
        "false_positive": (
            "Tools like ConnectWise and mshta.exe may be used legitimately. Validate based on context, source, and command-line parameters."
        ),
        "clearing_steps": [
            "Remove persistence mechanisms in registry and scheduled tasks.",
            "Terminate malicious scripts and tools (e.g., POWERSTATS, CrackMapExec).",
            "Rotate all potentially compromised credentials and audit privileged group memberships."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
