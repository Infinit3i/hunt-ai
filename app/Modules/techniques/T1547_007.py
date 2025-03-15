def get_content():
    return {
        "id": "T1547.007",
        "url_id": "1547/007",
        "title": "Boot or Logon Autostart Execution: Re-opened Applications",
        "description": "Adversaries may modify plist files to automatically run an application when a user logs in.",
        "tags": ["Persistence", "Privilege Escalation", "macOS"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "macOS",
        "os": "macOS",
        "tips": [
            "Monitor changes to plist files within '~/Library/Preferences/ByHost'.",
            "Track applications registered in 'com.apple.loginwindow.[UUID].plist' for anomalies.",
            "Detect unexpected application launches upon user login."
        ],
        "data_sources": "Command: Command Execution, File: File Modification",
        "log_sources": [
            {"type": "File", "source": "Plist Modifications", "destination": "Security Monitoring"},
            {"type": "Command", "source": "Execution Monitoring", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "File", "location": "~/Library/Preferences/ByHost/com.apple.loginwindow.[UUID].plist", "identify": "Modified Plist Entry"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "User Login Applications", "identify": "Unexpected Startup Application"}
        ],
        "detection_methods": [
            "Monitor plist file modifications for unexpected entries.",
            "Detect abnormal application launches on user login.",
            "Analyze process execution logs for unauthorized persistence mechanisms."
        ],
        "apt": ["Unknown"],
        "spl_query": [
            "index=macos_logs | search file_path='/Library/Preferences/ByHost/com.apple.loginwindow.*.plist'",
            "index=process_creation | search command contains 'open' AND argument contains '.plist'"
        ],
        "hunt_steps": [
            "Identify newly added or modified plist entries in the loginwindow directory.",
            "Check if applications listed in plist files are legitimate."
        ],
        "expected_outcomes": [
            "Detection of unauthorized plist modifications.",
            "Identification of adversaries using reopened applications for persistence."
        ],
        "false_positive": "Legitimate applications may modify plist files to restore session state.",
        "clearing_steps": [
            "Remove unauthorized entries from 'com.apple.loginwindow.[UUID].plist'.",
            "Audit and validate user-defined startup applications."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Execution via Malicious Plist Modification"},
            {"tactic": "Privilege Escalation", "technique": "T1106", "example": "Using Modified Plist for Privilege Escalation"}
        ],
        "watchlist": [
            "Monitor plist modifications that do not correlate with user activity.",
            "Alert on unauthorized applications attempting to execute at login."
        ],
        "enhancements": [
            "Implement integrity monitoring for plist file changes.",
            "Restrict user ability to modify plist startup entries without authorization."
        ],
        "summary": "Adversaries may modify plist files to automatically run an application when a user logs in.",
        "remediation": "Restrict unauthorized plist modifications and audit changes regularly.",
        "improvements": "Regularly review plist configurations for unauthorized persistence mechanisms."
    }
