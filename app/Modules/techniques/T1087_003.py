def get_content():
    return {
        "id": "T1087.003",  # Tactic Technique ID (e.g., T1087.003)
        "url_id": "T1087/003",  # URL segment for technique reference (e.g., 1087/003)
        "title": "Account Discovery: Email Account",  # Name of the attack technique
        "description": "Adversaries may gather email addresses from mail services or address lists to identify targets for phishing or lateral movement.",
        "tags": [
            "enterprise-attack",
            "Discovery",
            "Office Suite",
            "Windows"
        ],
        "tactic": "Discovery",
        "protocol": "",
        "os": "Windows, Office Suite",
        "tips": [
            "Monitor for PowerShell commands like 'Get-GlobalAddressList' in Exchange environments.",
            "Look for suspicious enumeration of corporate directories or address lists."
        ],
        "data_sources": "Exchange, Office 365, PowerShell, Process Creation",
        "log_sources": [
            {
                "type": "Process",
                "source": "Windows Event Logs",
                "destination": "SIEM or centralized logging"
            }
        ],
        "source_artifacts": [
            {
                "type": "Command",
                "location": "Local shell/CLI (e.g., PowerShell)",
                "identify": "Evidence of address list enumeration"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Log",
                "location": "Exchange or Office 365 Logs",
                "identify": "Email account discovery attempts"
            }
        ],
        "detection_methods": [
            "Monitor process creation logs for suspicious address list enumeration commands",
            "Alert on unusual or high-frequency address list queries"
        ],
        "apt": ["Nobelium"],
        "spl_query": [
            "index=win* process_command_line=\"*Get-GlobalAddressList*\" \n| stats count by user, host"
        ],
        "hunt_steps": [
            "Identify non-admin users performing address list queries",
            "Correlate enumerations with phishing or email compromise attempts"
        ],
        "expected_outcomes": [
            "Detection of unauthorized or anomalous email account enumeration"
        ],
        "false_positive": "System administrators or help desk staff may query address lists",
        "clearing_steps": [
            "Disable compromised credentials",
            "Review mail permissions and address list configurations"
        ],
        "mitre_mapping": [
            {
                "tactic": "Lateral Movement",
                "technique": "T1021 (Remote Services)",
                "example": "Use of discovered email accounts to pivot within the environment"
            }
        ],
        "watchlist": ["Repeated or automated enumeration of email accounts"],
        "enhancements": [
            "Implement role-based access controls on address lists",
            "Correlate address list queries with user login patterns"
        ],
        "summary": "Adversaries may seek email addresses to launch phishing or move laterally.",
        "remediation": "Enforce least-privilege access and monitor mailbox-related commands.",
        "improvements": "Integrate email service logs with SIEM for enhanced detection and correlation."
    }
