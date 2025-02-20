def get_content():
    return {
        "id": "T1078.003",
        "url_id": "1078/003",
        "title": "Valid Accounts: Local Accounts",
        "tags": ["Credential Access", "Persistence", "Privilege Escalation"],
        "tactic": "Persistence",
        "data_sources": "Authentication logs, Windows Event Logs, Process Monitoring",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Detect unauthorized access or persistence via compromised local accounts.",
        "scope": "Monitor local account usage for anomalies, particularly outside normal administrative activities.",
        "threat_model": "Adversaries may use or create local accounts to maintain persistence, escalate privileges, or move laterally without detection.",
        "hypothesis": [
            "Are there unauthorized logins from local accounts?",
            "Are local accounts being used to execute high-privileged commands?",
            "Are attackers creating new local administrator accounts for persistence?"
        ],
        "tips": [
            "Monitor for local account logins occurring outside expected administrative hours.",
            "Correlate local account usage with known attacker behaviors.",
            "Ensure local accounts have strong passwords and are protected against brute-force attacks."
        ],
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Event ID 4624 (Logon Success), Event ID 4720 (Account Creation), Event ID 4732 (Privilege Assignment)"},
            {"type": "Linux System Logs", "source": "/var/log/auth.log"},
            {"type": "macOS System Logs", "source": "/var/log/asl.log"}
        ],
        "source_artifacts": [
            {"type": "Registry", "location": "HKLM\\SAM\\Domains\\Account", "identify": "New local account creation"}
        ],
        "destination_artifacts": [
            {"type": "System Logs", "location": "/var/log/wtmp", "identify": "Local logins on Linux/macOS"}
        ],
        "detection_methods": [
            "Monitor local logins and alert on unauthorized access attempts.",
            "Detect changes in local group membership (e.g., users added to Administrators).",
            "Analyze patterns of local account usage that differ from normal behavior."
        ],
        "apt": [
            "FIN7", "APT33", "Lazarus Group"
        ],
        "spl_query": [
            "index=windows EventCode=4624 LogonType=2 OR LogonType=10 | stats count by Account_Name, Workstation_Name, Source_Network_Address"
        ],
        "hunt_steps": [
            "Identify newly created local accounts with administrative privileges.",
            "Review authentication logs for anomalies in local account access.",
            "Investigate instances of unauthorized account usage or privilege escalation.",
            "If malicious activity is confirmed → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Unauthorized Local Account Use Detected: Take action to remove the account and investigate further.",
            "No Malicious Activity Found: Continue monitoring and enhance detection mechanisms."
        ],
        "false_positive": "Legitimate administrative activity using local accounts, such as IT troubleshooting.",
        "clearing_steps": [
            "Disable or delete unauthorized local accounts.",
            "Enforce strict password policies for local accounts.",
            "Monitor for further suspicious authentication activity."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1078.003 (Valid Accounts: Local Accounts)", "example": "Adversaries using stolen local credentials to persist on systems."},
            {"tactic": "Privilege Escalation", "technique": "T1136 (Create Account)", "example": "Creating new local accounts for persistent access."},
            {"tactic": "Lateral Movement", "technique": "T1078 (Valid Accounts)", "example": "Using local accounts to move between systems undetected."}
        ],
        "watchlist": [
            "Monitor for new local account creations with administrator privileges.",
            "Track failed login attempts on local accounts.",
            "Alert on unusual authentication activity associated with local accounts."
        ],
        "enhancements": [
            "Implement multi-factor authentication (MFA) for privileged local accounts.",
            "Regularly audit local account usage and permissions.",
            "Restrict the use of local administrator accounts where possible."
        ],
        "summary": "Attackers use valid local accounts to maintain persistence and evade detection, leveraging stolen or newly created accounts for malicious activity.",
        "remediation": "Monitor and audit local account usage, enforce strong authentication policies, and disable unnecessary accounts.",
        "improvements": "Enhance anomaly detection for local account logins and integrate behavior-based alerts for unauthorized access attempts."
    }
