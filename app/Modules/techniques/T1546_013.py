def get_content():
    return {
        "id": "T1546.013",
        "url_id": "T1546/013",
        "title": "Event Triggered Execution: PowerShell Profile",
        "description": "Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles.",
        "tags": ["powershell", "persistence", "privilege escalation", "windows"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor PowerShell profile file locations for unauthorized changes",
            "Restrict write access to profile locations",
            "Use -NoProfile flag when launching trusted scripts"
        ],
        "data_sources": "Command, File, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "$Home\\Documents\\PowerShell\\Profile.ps1", "identify": "Check for unauthorized or modified commands"},
            {"type": "File", "location": "$PsHome\\Profile.ps1", "identify": "Global PowerShell profile"}
        ],
        "destination_artifacts": [
            {"type": "", "location": "", "identify": ""}
        ],
        "detection_methods": [
            "Monitor creation or changes to PowerShell profile scripts",
            "Detect abnormal PowerShell modules or command execution",
            "Watch for scripts run under high privilege accounts"
        ],
        "apt": ["Turla"],
        "spl_query": [
            "index=main sourcetype=WinEventLog:Security (CommandLine=*profile.ps1*)"
        ],
        "hunt_steps": [
            "Search for profile.ps1 creation/modification events",
            "Look for suspicious content inside PowerShell profiles",
            "Identify accounts executing altered profiles"
        ],
        "expected_outcomes": [
            "Detection of unauthorized profile modifications",
            "Identification of persistence mechanism using PowerShell profiles"
        ],
        "false_positive": "System administrators may intentionally modify profiles for automation; validate changes with change management records.",
        "clearing_steps": [
            "Delete or revert unauthorized profile.ps1 files",
            "Revoke persistence by removing malicious content from PowerShell profiles",
            "Audit user permissions on profile locations"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1027", "example": "Obfuscated PowerShell profile content"}
        ],
        "watchlist": [
            "$Home\\Documents\\PowerShell\\Profile.ps1",
            "$PsHome\\Profile.ps1"
        ],
        "enhancements": [
            "Enable script block logging for PowerShell",
            "Alert on PowerShell sessions not using -NoProfile with unusual commands"
        ],
        "summary": "Adversaries may abuse PowerShell profiles to execute malicious scripts each time PowerShell is launched, establishing persistence or escalating privileges.",
        "remediation": "Restrict write access to PowerShell profile locations, monitor changes, and use -NoProfile where possible.",
        "improvements": "Automate auditing of profile.ps1 files across systems and compare against known-good baselines.",
        "mitre_version": "16.1"
    }