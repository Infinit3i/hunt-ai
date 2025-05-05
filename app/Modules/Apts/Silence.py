def get_content():
    return {
        "id": "G0091",
        "url_id": "Silence",
        "title": "Silence",
        "tags": ["financial", "cybercrime", "Russia", "banking malware", "espionage"],
        "description": (
            "Silence is a financially motivated cybercriminal group first identified in 2016. It has targeted banking institutions "
            "across Russia, Ukraine, Belarus, Poland, Kazakhstan, and Azerbaijan. The group has been linked to attacks against ATMs, "
            "banking infrastructure including the Russian Central Bank’s Automated Workstation Client, and card processing systems. "
            "Silence operations often involve spearphishing, customized malware, and stealthy credential theft."
        ),
        "associated_groups": ["Whisper Spider"],
        "campaigns": [],
        "techniques": [
            "T1547.001", "T1059.001", "T1059.003", "T1059.005", "T1059.007", "T1070.004", "T1105", "T1036.005",
            "T1112", "T1106", "T1571", "T1027.010", "T1588.002", "T1003.001", "T1566.001", "T1055", "T1090.002",
            "T1021.001", "T1018", "T1053.005", "T1113", "T1072", "T1553.002", "T1218.001", "T1569.002",
            "T1204.002", "T1078", "T1125"
        ],
        "contributors": ["Oleg Skulkin, Group-IB"],
        "version": "2.2",
        "created": "24 May 2019",
        "last_modified": "17 November 2024",
        "navigator": "",
        "references": [
            {"source": "Group-IB", "url": "https://group-ib.com/resources/threat-reports/silence-darkside/"},
            {"source": "Kaspersky GReAT", "url": "https://securelist.com/silence-new-trojan-attacking-financial-orgs/"},
            {"source": "CrowdStrike Global Threat Report", "url": "https://www.crowdstrike.com/global-threat-report/"},
            {"source": "Group-IB Forensic", "url": "https://www.group-ib.com/resources/threat-reports/silence-2-0-going-global.pdf"},
            {"source": "Group-IB Technical", "url": "https://www.group-ib.com/blog/silence-malware-chm-analysis/"}
        ],
        "resources": [],
        "remediation": (
            "Segment internal networks, monitor for unusual RDP and PsExec activity, and enforce MFA. "
            "Disable macros in Office documents and restrict use of scripting languages via GPO. "
            "Detect and block use of remote admin tools like RAdmin or Winexe, and deploy least privilege principles for service accounts."
        ),
        "improvements": (
            "Deploy endpoint detection and response (EDR) tools to monitor process injection, credential dumping (LSASS), and command-line usage. "
            "Harden registry keys and log persistence mechanisms like Run keys and scheduled tasks. "
            "Regularly rotate domain and admin credentials to limit lateral movement."
        ),
        "hunt_steps": [
            "Identify command-line usage of PowerShell, VBS, or JavaScript in unusual paths or encoded form.",
            "Search for DLLs named like WINWORD.exe or signed with suspicious or stolen certificates.",
            "Look for LSASS memory access by unauthorized processes and ProxyBot activity on uncommon ports like 444."
        ],
        "expected_outcomes": [
            "Detection of phishing emails using CHM, LNK, or ZIP payloads.",
            "Identification of persistence via registry or task scheduler.",
            "Insight into credential access, screen/video capture, and lateral movement via RDP or PsExec."
        ],
        "false_positive": "PowerShell or scheduled task usage may be legitimate; validate context and correlation with persistence or exfiltration behaviors.",
        "clearing_steps": [
            "Terminate active sessions and remove downloaded malware components (e.g., Silence.Downloader).",
            "Purge scheduled tasks, registry keys, and startup folders modified by the attacker.",
            "Audit financial systems and revoke access for compromised accounts."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://group-ib.com/resources/threat-reports/silence-2-0-going-global.pdf",
                "https://securelist.com/silence-new-trojan-attacking-financial-orgs/"
            ]
        }
    }
