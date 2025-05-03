def get_content():
    return {
        "id": "G1016",
        "url_id": "FIN13",
        "title": "FIN13",
        "tags": ["financially motivated", "Mexico", "Latin America", "Elephant Beetle", "custom malware", "financial theft"],
        "description": (
            "FIN13 is a financially motivated cyber threat group that has been active since at least 2016, targeting financial, retail, and hospitality industries in Mexico and Latin America. "
            "They conduct long-term intrusions to steal intellectual property, financial data, PII, and execute fraudulent financial transactions. They are also linked to the group known as Elephant Beetle."
        ),
        "associated_groups": ["Elephant Beetle"],
        "campaigns": [],
        "techniques": [
            "T1134.003", "T1087", "T1087.002", "T1098.007", "T1071.001", "T1560.001", "T1547.001", "T1059.001",
            "T1059.003", "T1059.005", "T1136.001", "T1005", "T1565", "T1074.001", "T1140", "T1587.001",
            "T1190", "T1133", "T1083", "T1657", "T1589", "T1590.004", "T1564.001", "T1574.001", "T1105",
            "T1056.001", "T1036", "T1036.004", "T1036.005", "T1556", "T1046", "T1135", "T1588.002", "T1003.001",
            "T1003.002", "T1003.003", "T1069", "T1572", "T1090.001", "T1021.001", "T1021.002", "T1021.004",
            "T1021.006", "T1053.005", "T1505.003", "T1082", "T1016", "T1016.001", "T1049", "T1552.001",
            "T1550.002", "T1078.001", "T1047"
        ],
        "contributors": ["Oren Biderman, Sygnia", "Noam Lifshitz, Sygnia"],
        "version": "1.0",
        "created": "27 July 2023",
        "last_modified": "29 September 2023",
        "navigator": "",
        "references": [
            {
                "source": "Sygnia Incident Response Team",
                "url": "https://www.sygnia.co/resources/threat-intelligence/tg2003-elephant-beetle"
            },
            {
                "source": "FIN13: A Cybercriminal Threat Actor Focused on Mexico",
                "url": "https://unit42.paloaltonetworks.com/fin13-cybercriminal-group"
            }
        ],
        "resources": [],
        "remediation": (
            "Disable unneeded services like RDP, SSH, and WMI where possible. Ensure strong credential policies are enforced, including MFA. 
            Monitor task scheduler and registry Run keys for suspicious activity. Validate and secure exposed applications from known CVEs."
        ),
        "improvements": (
            "Deploy EDR tools with behavioral analysis to identify command-line misuse (e.g., certutil, reg.exe). 
            Harden SQL servers against xp_cmdshell abuse and enforce least privilege principles. 
            Conduct threat hunting for known FIN13 web shell names and internal proxy patterns."
        ),
        "hunt_steps": [
            "Scan systems for web shells: reGeorg, JspSpy, MiniWebCmdShell",
            "Check for abnormal scheduled tasks and DLL hijacking in IIS directories",
            "Identify registry persistence via HKLM\...\Run entries",
            "Search for usage of certutil decoding and archiving",
            "Monitor for Pass-the-Hash activity using tools like Invoke-SMBExec"
        ],
        "expected_outcomes": [
            "Detection of registry-based persistence mechanisms and credential dumping artifacts",
            "Identification of lateral movement via SMB, WMI, RDP, and SSH",
            "Recovery of staged data in temp folders pre-exfiltration"
        ],
        "false_positive": (
            "Scheduled tasks and PowerShell usage are common; rely on detection of suspicious naming, paths, and encoded commands for accuracy."
        ),
        "clearing_steps": [
            "Remove malicious web shells and scheduled tasks",
            "Revoke and rotate compromised credentials",
            "Delete staging folders and clean /tmp, Windows\Temp locations"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
