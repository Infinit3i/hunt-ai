def get_content():
    return {
        "id": "T1087.002",  # Tactic Technique ID (e.g., T1087.002)
        "url_id": "1087/002",  # URL segment for technique reference (e.g., 1087/002)
        "title": "Account Discovery: Domain Account",  # Name of the attack technique
        "description": "Adversaries may attempt to gather domain accounts. This helps identify privileged users for lateral movement or further compromise.",
        "tags": [
            "enterprise-attack",
            "Discovery",
            "Windows",
            "Linux",
            "macOS"
        ],
        "tactic": "Discovery",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor processes and command-line arguments for domain enumeration commands.",
            "Correlate domain account enumeration with suspicious logon or lateral movement activities."
        ],
        "data_sources": "Windows Security, Active Directory, Sysmon, etc.",
        "log_sources": [
            {
                "type": "Active Directory",
                "source": "Domain Controller Logs",
                "destination": "SIEM or centralized logging"
            }
        ],
        "source_artifacts": [
            {
                "type": "Command",
                "location": "Local shell/CLI",
                "identify": "Evidence of domain enumeration"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Log",
                "location": "Domain Controller",
                "identify": "Account enumeration events"
            }
        ],
        "detection_methods": [
            "Monitor process creation logs for enumeration commands",
            "Alert on unusual or high-frequency usage of 'net user /domain', etc."
        ],
        "apt": ["APT41", "Ke3chang"],
        "spl_query": [
            "index=win* process_command_line=\"*net user /domain*\" \n| stats count by user, host"
        ],
        "hunt_steps": [
            "Identify accounts executing enumeration commands outside normal hours"
        ],
        "expected_outcomes": [
            "Detection of unauthorized or anomalous domain account enumeration"
        ],
        "false_positive": "Legitimate domain administration tasks",
        "clearing_steps": [
            "Disable compromised credentials",
            "Review permissions for domain users"
        ],
        "mitre_mapping": [
            {
                "tactic": "Lateral Movement",
                "technique": "T1021 (Remote Services)",
                "example": "Use of discovered domain accounts to move laterally"
            }
        ],
        "watchlist": ["Repeated or automated enumeration commands"],
        "enhancements": [
            "Implement role-based access controls",
            "Correlate enumeration events with logon activities"
        ],
        "summary": "Enumerating domain accounts to identify targets for privilege escalation or lateral movement.",
        "remediation": "Use strong credential hygiene, centralized logging, and MFA.",
        "improvements": "Integrate AD logs, Sysmon, and process creation logs into a SIEM."
    }
