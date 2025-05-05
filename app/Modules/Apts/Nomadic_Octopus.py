def get_content():
    return {
        "id": "G0133",
        "url_id": "Nomadic_Octopus",
        "title": "Nomadic Octopus",
        "tags": ["espionage", "Central Asia", "Russia-linked", "Delphi", "Android", "Windows", "custom-malware"],
        "description": (
            "Nomadic Octopus is a Russian-speaking cyber espionage group that has operated since at least 2014, "
            "primarily targeting Central Asia, including local governments, diplomatic missions, and individuals. "
            "The group has developed and deployed custom malware—predominantly in the Delphi language—on Android and Windows platforms. "
            "Its tactics include spearphishing and the use of malware masquerading as legitimate applications like Telegram Messenger."
        ),
        "associated_groups": ["DustSquad"],
        "campaigns": [],
        "techniques": [
            "T1059.001",  # PowerShell
            "T1059.003",  # Windows Command Shell
            "T1564.003",  # Hidden Window
            "T1105",      # Ingress Tool Transfer
            "T1036",      # Masquerading
            "T1566.001",  # Spearphishing Attachment
            "T1204.002"   # Malicious File Execution
        ],
        "contributors": [],
        "version": "1.0",
        "created": "24 August 2021",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {"source": "Security Affairs", "url": "https://securityaffairs.com/67693/apt/dustsquad-central-asia.html"},
            {"source": "Kaspersky GReAT", "url": "https://securelist.com/octopus-infested-seas-of-central-asia/88151/"},
            {"source": "ESET", "url": "https://www.welivesecurity.com/2018/10/04/nomadic-octopus-cyberespionage-central-asia/"},
            {"source": "SecurityWeek", "url": "https://www.securityweek.com/russia-linked-hackers-target-diplomatic-entities-central-asia/"}
        ],
        "resources": [],
        "remediation": (
            "Block execution of macros in office documents by default. "
            "Enhance mail gateway filtering to detect and quarantine spearphishing attachments. "
            "Harden endpoint defenses to detect masquerading executables mimicking common applications like Telegram."
        ),
        "improvements": (
            "Deploy advanced heuristic detection for Delphi-based malware. "
            "Monitor PowerShell and cmd.exe executions in the context of Office macros or spearphishing delivery vectors."
        ),
        "hunt_steps": [
            "Search endpoint logs for execution of PowerShell in hidden windows.",
            "Look for execution chains involving cmd.exe triggered by Office processes.",
            "Audit for known Octopus malware indicators, particularly those mimicking Russian-language Telegram interfaces."
        ],
        "expected_outcomes": [
            "Detection of spearphishing-based initial access vectors.",
            "Attribution of command-line and macro execution to Nomadic Octopus malware variants.",
            "Improved telemetry on phishing campaigns targeting Central Asian diplomatic sectors."
        ],
        "false_positive": (
            "Use of PowerShell and cmd.exe is common in enterprise environments. "
            "Behavioral context such as hidden window execution or macro-based invocation should guide investigation."
        ),
        "clearing_steps": [
            "Delete downloaded payloads dropped by malicious macros.",
            "Reimage compromised systems if Octopus malware is detected.",
            "Update all endpoint security signatures to detect Octopus variants."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
