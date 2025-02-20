def get_content():
    return {
        "id": "T1078.001",
        "url_id": "T1078/001",
        "title": "Valid Accounts: Default Accounts",
        "tags": ["Credential Access", "Persistence"],
        "tactic": "Persistence",
        "data_sources": "Authentication logs, System logs, Active Directory logs",
        "protocol": "Various",
        "os": "Windows, Linux, macOS",
        "objective": "Identify and mitigate adversaries leveraging default accounts for unauthorized access.",
        "scope": "Monitor and restrict the use of default accounts to prevent unauthorized system access.",
        "threat_model": "Adversaries may use default credentials, often left unchanged, to gain initial access or persist within a system.",
        "hypothesis": [
            "Are default accounts being used for authentication?",
            "Are there failed login attempts on default accounts?",
            "Are default accounts logging in from unusual locations or times?"
        ],
        "tips": [
            "Regularly audit and disable unused default accounts.",
            "Enforce strong passwords for all default accounts.",
            "Monitor for login attempts using known default credentials."
        ],
        "log_sources": [
            {"type": "Authentication Logs", "source": "Event ID 4625 (Failed Login), Event ID 4624 (Successful Login)", "destination": "SIEM"},
            {"type": "System Logs", "source": "/var/log/auth.log (Linux)", "destination": "SIEM"},
            {"type": "Active Directory Logs", "source": "Domain Controller Authentication Logs", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "Account Usage", "location": "Local SAM Database", "identify": "Presence of default credentials"}
        ],
        "destination_artifacts": [
            {"type": "Access Logs", "location": "Domain Controller Logs", "identify": "Logins using default accounts"}
        ],
        "detection_methods": [
            "Monitor authentication logs for default account usage.",
            "Detect repeated login attempts using common default credentials.",
            "Correlate default account logins with anomalous activities."
        ],
        "apt": ["APT33", "Lazarus Group", "FIN7"],
        "spl_query": [
            "index=auth_logs source=* event_id=4624 user=Administrator OR user=Guest",
            "index=linux_logs source=/var/log/auth.log user=root"
        ],
        "hunt_steps": [
            "Identify all active default accounts in the environment.",
            "Check for unusual login patterns associated with default accounts.",
            "Correlate default account activity with other suspicious events."
        ],
        "expected_outcomes": [
            "Unauthorized use of default accounts is detected and mitigated.",
            "No malicious activity is found, default account policies are reinforced."
        ],
        "false_positive": "Legitimate administrative use of default accounts for system maintenance.",
        "clearing_steps": [
            "Disable or rename default accounts where applicable.",
            "Enforce multi-factor authentication for all privileged accounts.",
            "Implement strict password policies for default accounts."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1078 (Valid Accounts)", "example": "Adversaries use default credentials to gain access."},
            {"tactic": "Privilege Escalation", "technique": "T1078.003 (Local Accounts)", "example": "Attackers escalate privileges using default admin accounts."}
        ],
        "watchlist": [
            "Monitor login attempts from known default accounts.",
            "Track authentication failures related to default credentials.",
            "Alert on default account usage from unexpected IP addresses."
        ],
        "enhancements": [
            "Regularly review and rotate passwords for built-in accounts.",
            "Implement Just-In-Time (JIT) access for privileged accounts.",
            "Use behavioral analytics to detect anomalies in default account usage."
        ],
        "summary": "Default accounts present a significant security risk when left unchanged. Attackers frequently exploit these accounts for initial access and persistence.",
        "remediation": "Audit and secure default accounts by enforcing strong authentication measures and monitoring usage.",
        "improvements": "Enhance visibility into account usage through SIEM integration and automate alerts for default account anomalies."
    }
