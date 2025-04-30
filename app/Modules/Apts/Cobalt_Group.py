def get_content():
    return {
        "id": "G0080",
        "url_id": "Cobalt_Group",
        "title": "Cobalt Group",
        "tags": ["financially-motivated", "banking", "APT", "Eastern Europe", "Asia", "malware"],
        "description": "Cobalt Group is a financially motivated threat group that has primarily targeted financial institutions since at least 2016. Known for leveraging malware and exploits to steal funds via ATM systems, card processing, SWIFT systems, and more, the group remains active despite arrests. It frequently uses phishing, Cobalt Strike, and sophisticated malware toolchains.",
        "associated_groups": ["GOLD KINGSWOOD", "Cobalt Gang", "Cobalt Spider"],
        "campaigns": [],
        "techniques": [
            "T1548.002", "T1071.001", "T1071.004", "T1547.001", "T1037.001",
            "T1059.001", "T1059.003", "T1059.005", "T1059.007", "T1543.003",
            "T1573.002", "T1203", "T1068", "T1070.004", "T1105", "T1559.002",
            "T1046", "T1027.010", "T1588.002", "T1566.001", "T1566.002",
            "T1055", "T1572", "T1219", "T1021.001", "T1053.005", "T1518.001",
            "T1195.002", "T1218.003", "T1218.008", "T1218.010", "T1204.001",
            "T1204.002", "T1220"
        ],
        "contributors": [],
        "version": "2.1",
        "created": "17 October 2018",
        "last_modified": "16 April 2025",
        "navigator": "",  # Add MITRE Navigator link if available
        "references": [
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0080/"},
            {"source": "Positive Technologies", "url": "https://www.ptsecurity.com/ww-en/about/news/cobalt-strikes-back/"},
            {"source": "CrowdStrike", "url": "https://www.crowdstrike.com/blog/2020-global-threat-report/"},
            {"source": "Europol", "url": "https://www.europol.europa.eu/newsroom/news/mastermind-behind-eur-1-billion-cyber-bank-robbery-arrested-in-spain"}
        ],
        "resources": [],
        "remediation": "Organizations should implement strict application whitelisting, email filtering, and employee awareness training. Segment networks, restrict use of scripting engines (e.g., PowerShell), and use endpoint detection tools to identify known Cobalt Strike or JavaScript backdoors.",
        "improvements": "Enhance monitoring for script execution, service creation, and suspicious DLL loading. Deploy behavior-based detection for lateral movement and privilege escalation.",
        "hunt_steps": [
            "Look for suspicious use of cmstp.exe, regsvr32.exe, and odbcconf.",
            "Search for network connections using plink.exe for SSH tunneling.",
            "Audit for scheduled tasks and new Windows Services without documentation.",
            "Check email logs for spearphishing attachments and links."
        ],
        "expected_outcomes": [
            "Detection of persistent footholds via registry keys and scheduled tasks.",
            "Identification of lateral movement via RDP and PsExec.",
            "Discovery of obfuscated payloads or tools like Cobalt Strike and Mimikatz.",
            "Removal of access vectors and credential artifacts."
        ],
        "false_positive": "Legitimate administrative use of PowerShell, regsvr32.exe, or scheduled tasks can generate noise. Correlate with user behavior and asset roles.",
        "clearing_steps": [
            "Remove malicious registry keys and scheduled tasks.",
            "Terminate unauthorized services and processes.",
            "Reset compromised user credentials and RDP access.",
            "Delete downloaded malware from staging directories."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://attack.mitre.org/groups/G0080/",
                "https://unit42.paloaltonetworks.com/cobalt-strikes-again/",
                "https://www.crowdstrike.com/blog/cobalt-group-threat-intel/"
            ]
        }
    }
