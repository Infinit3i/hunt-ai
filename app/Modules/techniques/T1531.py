def get_content():
    return {
        "id": "T1531",
        "url_id": "1531",
        "title": "Account Access Removal",
        "description": (
            "Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. "
            "Accounts may be deleted, locked, or manipulated (e.g., changed credentials) to remove access. Adversaries may also log off and/or "
            "perform a [System Shutdown/Reboot](https://attack.mitre.org/techniques/T1529) to enforce malicious changes. "
            "In Windows, [Net](https://attack.mitre.org/software/S0039), `Set-LocalUser`, and `Set-ADAccountPassword` PowerShell cmdlets may be used "
            "by adversaries to modify user accounts. In Linux, the `passwd` utility may be used to change passwords. Accounts could also be disabled "
            "by Group Policy. "
            "Adversaries using ransomware or similar attacks may first perform this and other Impact behaviors, such as [Data Destruction](https://attack.mitre.org/techniques/T1485) "
            "and [Defacement](https://attack.mitre.org/techniques/T1491), to impede incident response/recovery before completing the "
            "[Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486) objective."
        ),
        "tags": ["Impact", "Account Lockout", "Credential Manipulation", "Windows", "Linux", "macOS"],
        "tactic": "Impact",
        "protocol": "Windows API, PowerShell, Linux CLI",
        "os": "IaaS, Linux, Office Suite, SaaS, Windows, macOS",
        "tips": [
            "Monitor for unexpected account deletions or password changes.",
            "Track usage of administrative tools like `Net`, `passwd`, and PowerShell account modification cmdlets.",
            "Establish user account baselines to detect anomalies in deletion and modification patterns.",
            "Monitor event logs for multiple account changes in a short timeframe."
        ],
        "data_sources": "Active Directory: Active Directory Object Modification, User Account: User Account Deletion, User Account: User Account Modification",
        "log_sources": [
            {"type": "Security Event Logs", "source": "Windows Event Log", "destination": "SIEM"},
            {"type": "Active Directory Logs", "source": "Domain Controller", "destination": "SIEM"},
            {"type": "Linux Audit Logs", "source": "/var/log/auth.log", "destination": "Forensic Analysis"},
        ],
        "source_artifacts": [
            {"type": "Account Modification", "location": "Event Logs", "identify": "Unauthorized account deletion or lockout"},
            {"type": "Process Execution", "location": "Command-line logs", "identify": "Use of account management tools"},
        ],
        "destination_artifacts": [
            {"type": "User Account Unavailability", "location": "Access Control Logs", "identify": "Multiple failed login attempts due to lockout"},
        ],
        "detection_methods": [
            "Monitor Event Logs for account deletion, password resets, and lockouts:",
            "- Event ID 4723 - An attempt was made to change an account’s password",
            "- Event ID 4724 - An attempt was made to reset an account’s password",
            "- Event ID 4726 - A user account was deleted",
            "- Event ID 4740 - A user account was locked out",
            "Monitor PowerShell logs for `Set-ADAccountPassword` or `Set-LocalUser` executions.",
            "Monitor for abnormal use of the `passwd` command in Linux environments."
        ],
        "apt": ["APT groups known for disrupting user access"],
        "spl_query": [
            "index=windows_logs (EventCode=4723 OR EventCode=4724 OR EventCode=4726 OR EventCode=4740) \n| stats count by Account_Name, Change_Type",
        ],
        "hunt_steps": [
            "Investigate recent user account deletions or modifications.",
            "Identify excessive failed login attempts leading to lockouts.",
            "Check administrative user activity around impacted accounts.",
            "Correlate account lockouts with other malicious activity."
        ],
        "expected_outcomes": [
            "Unauthorized Account Deletion Detected: Investigate and take action to restore impacted accounts.",
            "No Malicious Activity Found: Confirm legitimate administrative changes."
        ],
        "false_positive": "Legitimate administrative actions may result in account deletions or password resets; verify against change records and privileged account usage.",
        "clearing_steps": [
            "Restore deleted accounts from backups or recreate as needed.",
            "Investigate root cause of unexpected account lockouts and prevent further unauthorized changes.",
            "Implement multi-factor authentication (MFA) to reduce unauthorized account modifications.",
            "Ensure administrative access to account management tools is properly restricted."
        ],
        "mitre_mapping": [
            {"tactic": "Impact", "technique": "T1531", "example": "Disabling accounts to prevent legitimate user access."},
        ],
        "watchlist": [
            "Monitor for multiple account deletions or lockouts in a short period.",
            "Detect spikes in password reset attempts by non-administrators.",
            "Investigate correlation between account access changes and ransomware or wiper malware activities."
        ],
        "enhancements": [
            "Enable audit logging for all user account modifications.",
            "Restrict access to `Net`, `passwd`, and PowerShell account management commands.",
            "Use SIEM correlation rules to detect mass account deletions or unauthorized password resets."
        ],
        "summary": "Adversaries may delete, lock, or modify user accounts to disrupt system access and inhibit incident response efforts.",
        "remediation": "Audit and restore affected user accounts, enforce access controls, and implement stronger account protection measures.",
        "improvements": "Enhance real-time alerting and monitoring of user account changes to quickly detect and mitigate unauthorized account access removals."
    }
