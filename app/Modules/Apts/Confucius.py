def get_content():
    return {
        "id": "G0142",
        "url_id": "Confucius",
        "title": "Confucius",
        "tags": ["cyber-espionage", "South Asia", "government", "military", "APT"],
        "description": "Confucius is a cyber espionage group active since at least 2013, targeting military personnel, high-profile individuals, and government entities across South Asia. It shares similarities with the Patchwork group in malware code and targeting strategies. The group employs various phishing tactics and custom tools to conduct exfiltration and espionage.",
        "associated_groups": ["Confucius APT"],
        "campaigns": [],
        "techniques": [
            "T1583.006", "T1071.001", "T1119", "T1547.001", "T1059.001",
            "T1059.005", "T1041", "T1567.002", "T1203", "T1083", "T1105",
            "T1566.001", "T1566.002", "T1053.005", "T1218.005", "T1082",
            "T1221", "T1204.001", "T1204.002"
        ],
        "contributors": [],
        "version": "1.1",
        "created": "26 December 2021",
        "last_modified": "16 April 2025",
        "navigator": "",  # Add MITRE Navigator link if available
        "references": [
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0142/"},
            {"source": "Deciphering Confucius", "url": "https://www.welivesecurity.com/2018/02/13/deciphering-confucius-look-cyberespionage-operations/"},
            {"source": "Uptycs Threat Research", "url": "https://www.uptycs.com/blog/confucius-apt-warzone-rat"},
            {"source": "Lookout Research", "url": "https://blog.lookout.com/blog/2021/02/10/novel-confucius-apt-android-spyware"}
        ],
        "resources": [],
        "remediation": "Deploy multi-layered phishing detection mechanisms, limit scripting execution via GPOs or application whitelisting, and monitor endpoint behaviors for file and process anomalies. Regular patching and user education are essential.",
        "improvements": "Implement email sandboxing, enforce cloud storage access policies, and use behavioral analytics to detect anomalous file access and exfiltration attempts.",
        "hunt_steps": [
            "Review scheduled tasks and registry run keys for unauthorized persistence.",
            "Monitor for mshta.exe and PowerShell spawning from Office products.",
            "Look for anomalous HTTP traffic associated with known exfiltration endpoints.",
            "Inspect cloud storage connections from endpoints not typically using them."
        ],
        "expected_outcomes": [
            "Identification of infected systems using custom stealer tools.",
            "Early detection of phishing campaigns leveraging lures and malicious links.",
            "Removal of VBScript or mshta persistence mechanisms.",
            "Blocking of exfiltration channels to cloud storage services."
        ],
        "false_positive": "Use of PowerShell or mshta.exe may occur in benign administrative tasks. Validation should include correlation with user behavior and timing.",
        "clearing_steps": [
            "Delete malicious files from Startup folders and scheduled tasks.",
            "Block malicious domains and reset credentials for affected users.",
            "Purge cloud storage sessions and reset authentication tokens.",
            "Reimage endpoints if persistent malware (e.g., WarzoneRAT) is confirmed."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://attack.mitre.org/groups/G0142/",
                "https://www.uptycs.com/blog/confucius-apt-warzone-rat"
            ]
        }
    }
