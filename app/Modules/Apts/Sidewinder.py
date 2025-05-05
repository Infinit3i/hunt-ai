def get_content():
    return {
        "id": "G0121",
        "url_id": "Sidewinder",
        "title": "Sidewinder",
        "tags": ["India-linked", "espionage", "South Asia", "government targeting", "phishing"],
        "description": (
            "Sidewinder is a suspected Indian APT group active since at least 2012. "
            "The group has targeted government, military, and business entities throughout Asia, "
            "with a focus on Pakistan, China, Nepal, and Afghanistan. Sidewinder is known for phishing campaigns, "
            "sophisticated obfuscation, and the use of multiple scripting environments to drop and execute malware payloads."
        ),
        "associated_groups": ["T-APT-04", "Rattlesnake"],
        "campaigns": [],
        "techniques": [
            "T1071.001", "T1119", "T1020", "T1547.001", "T1059.001", "T1059.005", "T1059.007",
            "T1074.001", "T1203", "T1083", "T1574.001", "T1105", "T1559.002", "T1036.005",
            "T1027.010", "T1027.013", "T1566.001", "T1566.002", "T1598.002", "T1598.003",
            "T1057", "T1518", "T1518.001", "T1218.005", "T1082", "T1016", "T1033",
            "T1124", "T1204.001", "T1204.002"
        ],
        "contributors": [
            "Lacework Labs",
            "Daniyal Naeem, BT Security"
        ],
        "version": "1.2",
        "created": "27 January 2021",
        "last_modified": "11 April 2024",
        "navigator": "",
        "references": [
            {"source": "Unit42 - Global Perspective", "url": "https://unit42.paloaltonetworks.com/sidewinder-apt/"},
            {"source": "Kaspersky APT Trends Q1 2018", "url": "https://securelist.com/apt-trends-report-q1-2018/"},
            {"source": "Cyble Research", "url": "https://cyble.com/blog/2020/09/26/sidewinder-apt-targets/"},
            {"source": "Rewterz Campaign Analysis", "url": "https://www.rewterz.com/reports/sidewinder-apt-covid19-analysis"},
            {"source": "Rewterz Technical Analysis", "url": "https://www.rewterz.com/analysis-on-sidewinder-apt-group"}
        ],
        "resources": [],
        "remediation": (
            "Apply patches for commonly exploited vulnerabilities (e.g., CVE-2017-11882, CVE-2020-0674). "
            "Block execution of mshta.exe and monitor script interpreter usage like PowerShell, VBScript, and JavaScript. "
            "Implement user training for identifying spearphishing links and attachments."
        ),
        "improvements": (
            "Enable endpoint logging and EDR rules to monitor abnormal registry modifications and file execution flows. "
            "Deploy DNS filtering and secure email gateways with attachment and link detonation capabilities."
        ),
        "hunt_steps": [
            "Hunt for process chains involving Office applications launching scripting interpreters.",
            "Search for DLL side-loading using known Windows executables such as rekeywiz.exe.",
            "Check for suspicious use of mshta.exe or payloads encoded with base64 or custom encryption."
        ],
        "expected_outcomes": [
            "Identification of phishing campaigns using malicious scripts or document exploits.",
            "Detection of malware staging and exfiltration behaviors involving temporary folders.",
            "Insight into command obfuscation and execution via trusted binaries."
        ],
        "false_positive": "PowerShell and JavaScript are legitimate scripting tools; evaluate behavioral context and external connections.",
        "clearing_steps": [
            "Terminate malicious processes and delete associated scripts or payloads.",
            "Remove persistence entries from registry keys or startup folders.",
            "Re-image compromised systems and reset credentials associated with affected accounts."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://unit42.paloaltonetworks.com/sidewinder-apt/",
                "https://cyble.com/blog/2020/09/26/sidewinder-apt-targets/"
            ]
        }
    }
