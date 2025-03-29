def get_content():
    return {
        "id": "T1098.002",
        "url_id": "T1098/002",
        "title": "Account Manipulation: Additional Email Delegate Permissions",
        "description": (
            "Adversaries may grant additional permission levels to maintain persistent access to an email account, "
            "such as using the 'Add-MailboxPermission' PowerShell cmdlet in Exchange or Office 365, or delegation features "
            "in Google Workspace."
        ),
        "tags": [
            "enterprise-attack",
            "Persistence",
            "Privilege Escalation",
            "Office 365",
            "Email"
        ],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Office Suite, Windows",
        "tips": [
            "Monitor mailbox audit logs (e.g., UpdateFolderPermissions events) for suspicious changes.",
            "Look for unexpected delegation or folder permission assignments, especially to Default or Anonymous."
        ],
        "data_sources": (
            "Exchange/Office 365 Audit Logs, Google Workspace Admin Logs, PowerShell Logs, Application Log"
        ),
        "log_sources": [
            {
                "type": "Office Suite",
                "source": "Office 365 Unified Audit Log (or Exchange Server logs)",
                "destination": "SIEM or centralized logging solution"
            }
        ],
        "source_artifacts": [
            {
                "type": "Command",
                "location": "PowerShell, Exchange Management Shell, Google Admin Console",
                "identify": "Evidence of Add-MailboxPermission or mailbox delegation modifications"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Log",
                "location": "Mailbox Audit Logs (e.g., UpdateFolderPermissions actions)",
                "identify": "Creation or modification of delegate permissions"
            }
        ],
        "detection_methods": [
            "Alert on mailbox permission changes that assign roles or permissions to unexpected accounts.",
            "Correlate sudden delegation changes with suspicious sign-in attempts or network anomalies."
        ],
        "apt": [
            "APT35",
            "UNC2452",
            "APT29"
        ],
        "spl_query": [
            # Example Splunk query (using literal \n| for multiline)
            "index=o365 sourcetype=\"o365:management:activity\" \"UpdateFolderPermissions\" \n| stats count by UserId, ClientIp"
        ],
        "hunt_steps": [
            "Identify mailboxes that have had Default or Anonymous user permissions changed recently.",
            "Check for any unexpected delegate permissions added by non-administrative users."
        ],
        "expected_outcomes": [
            "Detection of unauthorized mailbox delegate permissions that may indicate persistent email compromise."
        ],
        "false_positive": (
            "Legitimate mailbox delegation by IT or helpdesk staff for administrative or support purposes. "
            "Review context and timing to confirm authenticity."
        ),
        "clearing_steps": [
            "Remove unauthorized delegates or permission assignments from affected mailboxes.",
            "Rotate or reset credentials for compromised accounts."
        ],
        "mitre_mapping": [
            {
                "tactic": "Privilege Escalation",
                "technique": "T1078 (Valid Accounts)",
                "example": "Using newly added delegate permissions to escalate privileges or maintain persistence."
            }
        ],
        "watchlist": [
            "Mailbox permission changes involving Default or Anonymous roles.",
            "Repeated or scripted mailbox delegation assignments across multiple user accounts."
        ],
        "enhancements": [
            "Enable mailbox auditing for all users, including the UpdateFolderPermissions action.",
            "Use conditional access or MFA to protect administrative actions in Exchange/Office 365."
        ],
        "summary": (
            "Adversaries may add or modify email delegate permissions to maintain persistent access or escalate "
            "privileges within an email environment."
        ),
        "remediation": (
            "Audit and remove any unauthorized delegate permissions. "
            "Enable and regularly review mailbox audit logs to detect suspicious permission changes."
        ),
        "improvements": (
            "Integrate email audit logs (Office 365, Exchange, Google Workspace) with a SIEM to correlate with "
            "other security events. Configure alerts for mailbox delegation changes."
        )
    }
