def get_content():
    return {
        "id": "T1136.002",
        "url_id": "1136/002",
        "title": "Create Account: Domain Account",
        "description": "Adversaries may create a domain account to maintain access to victim systems. Domain accounts are managed by Active Directory Domain Services, where access and permissions are configured across systems and services in that domain. Attackers may use the `net user /add /domain` command to create a domain account.",
        "tags": ["Persistence", "Active Directory", "User Account Creation"],
        "tactic": "Persistence",
        "protocol": "LDAP, SMB",
        "os": ["Windows", "Linux", "macOS"],
        "tips": [
            "Monitor for processes and command-line parameters associated with domain account creation.",
            "Event ID 4720 is generated when a user account is created on a Windows domain controller.",
            "Perform regular audits of domain accounts to detect suspicious activity."
        ],
        "data_sources": "User Account, Process Creation, Active Directory, Windows Security Logs",
        "log_sources": [
            {"type": "Windows Security", "source": "Event ID 4720", "destination": "Domain Controller"},
            {"type": "Process", "source": "Command Execution", "destination": "System Logs"}
        ],
        "source_artifacts": [
            {"type": "Event Log", "location": "Windows Security Log", "identify": "Event ID 4720"}
        ],
        "destination_artifacts": [
            {"type": "Account Object", "location": "Active Directory", "identify": "New Domain Account"}
        ],
        "detection_methods": [
            "Monitor Event ID 4720 for domain account creation.",
            "Detect suspicious `net user /add /domain` command execution.",
            "Correlate new account creation with process execution logs."
        ],
        "apt": ["Soft Cell", "GALLIUM", "FIN12", "Exchange Marauder", "Fivehands", "Crashoverride"],
        "spl_query": [
            "index=windows EventCode=4720 | table _time, Account_Name, Caller_User_Name, ComputerName"
        ],
        "hunt_steps": [
            "Review newly created domain accounts in Active Directory.",
            "Check for unauthorized account creation by adversaries.",
            "Analyze command-line history for `net user /add /domain` executions."
        ],
        "expected_outcomes": [
            "Identification of unauthorized domain accounts.",
            "Detection of attacker persistence mechanisms."
        ],
        "false_positive": "Legitimate user account creation by IT administrators.",
        "clearing_steps": [
            "Disable and delete unauthorized domain accounts.",
            "Review and revoke unnecessary permissions on domain accounts.",
            "Investigate the source of unauthorized account creation."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "Create Account", "example": "An attacker creates a new domain account for persistence."}
        ],
        "watchlist": ["Newly created domain accounts with unexpected privileges."],
        "enhancements": ["Implement stricter auditing policies for domain account creation."],
        "summary": "Attackers may create domain accounts to maintain persistent access. Monitoring Event ID 4720 and command execution logs can help detect this technique.",
        "remediation": "Review and remove unauthorized accounts. Enforce strict account creation policies.",
        "improvements": "Enable advanced logging for user account modifications in Active Directory."
    }
