def get_content():
    return {
        "id": "T1087.001",  # Tactic Technique ID (e.g., T1087.001)
        "url_id": "1087/001",  # URL segment for technique reference (e.g., 1087/001)
        "title": "Account Discovery: Local Account",  # Name of the attack technique
        "description": "Adversaries may gather local system accounts to identify targets for lateral movement or privilege escalation.",
        "tags": [
            "enterprise-attack",
            "Discovery",
            "Linux",
            "Windows",
            "macOS"
        ],
        "tactic": "Discovery",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor for commands like 'net user', 'net localgroup', 'dscl . list /Users', or 'id/groups' on Linux/macOS."
        ],
        "data_sources": (
            "Windows Security, Windows System, Sysmon, Active Directory, Linux/macOS System Logs, Command, Process"
        ),
        "log_sources": [
            {
                "type": "Process",
                "source": "System Event Logs",
                "destination": "SIEM or centralized logging"
            }
        ],
        "source_artifacts": [
            {
                "type": "Command",
                "location": "Local shell/CLI (e.g., net.exe, dscl, id)",
                "identify": "Evidence of local account enumeration"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Log",
                "location": "System logs",
                "identify": "Events indicating local account enumeration"
            }
        ],
        "detection_methods": [
            "Monitor process creation logs for local account enumeration commands",
            "Alert on unusual or high-frequency usage of 'net user' or 'net localgroup'"
        ],
        "apt": ["Ke3chang", "APT41"],
        "spl_query": [
            "index=win* EventCode=4688 process_command_line=\"*net user*\" \n| stats count by user, host"
        ],
        "hunt_steps": [
            "Identify non-admin users executing local account enumeration commands",
            "Correlate enumeration attempts with lateral movement activities"
        ],
        "expected_outcomes": [
            "Detection of unauthorized or anomalous local account enumeration"
        ],
        "false_positive": "System administrators may legitimately list local accounts",
        "clearing_steps": [
            "Disable compromised accounts",
            "Review local permissions and privileges"
        ],
        "mitre_mapping": [
            {
                "tactic": "Lateral Movement",
                "technique": "T1021 (Remote Services)",
                "example": "Using enumerated local accounts for remote access"
            }
        ],
        "watchlist": ["Repeated or automated local account enumeration"],
        "enhancements": [
            "Enforce least-privilege and role-based access controls",
            "Correlate local account enumeration with subsequent privilege escalation"
        ],
        "summary": "Enumerating local accounts to identify targets for lateral movement or privilege escalation.",
        "remediation": "Use strong credential hygiene, enable centralized logging, and monitor local account enumeration commands.",
        "improvements": "Combine process creation logs with Sysmon data for enhanced detection of local account discovery."
    }
