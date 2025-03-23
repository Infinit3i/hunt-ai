def get_content():
    return {
        "id": "T1114.003",
        "url_id": "T1114/003",
        "title": "Email Collection: Email Forwarding Rule",
        "description": "Adversaries may setup email forwarding rules to collect sensitive information. This technique may also allow persistent access to victim emails even after credential resets.",
        "tags": ["email", "forwarding", "persistence", "collection", "exchange"],
        "tactic": "Collection",
        "protocol": "",
        "os": "Linux, Office Suite, Windows, macOS",
        "tips": [
            "Monitor email rule creation via logs or API calls like Get-InboxRule.",
            "Search for mail headers like X-MS-Exchange-Organization-AutoForwarded or X-Forwarded-To.",
            "Check for mailbox rules that forward emails to external domains."
        ],
        "data_sources": "Application Log: Application Log Content, Cloud Service: Cloud Service Metadata, Command: Command Execution",
        "log_sources": [
            {"type": "Cloud Service", "source": "Cloud Service Metadata", "destination": "Application Log"},
            {"type": "Command", "source": "Command Execution", "destination": "Application Log"}
        ],
        "source_artifacts": [
            {"type": "Inbox Rule", "location": "Outlook/OWA/MAPI", "identify": "Forward to external domain"}
        ],
        "destination_artifacts": [
            {"type": "Auto-Forwarded Emails", "location": "Message Headers", "identify": "X-MS-Exchange-Organization-AutoForwarded"}
        ],
        "detection_methods": [
            "Inbox rule analysis (e.g., PowerShell Get-InboxRule)",
            "Message header inspection for forwarding artifacts",
            "Message tracking logs and rule property auditing"
        ],
        "apt": [
            "Star Blizzard", "Kimsuky", "DEV-0537", "BEC actors"
        ],
        "spl_query": [
            "index=o365 sourcetype=ms:o365:exchange ruleName=*Forward* OR forwardingSmtpAddress=*\n| stats count by user, ruleName, forwardingSmtpAddress",
            "index=email_headers \"X-MS-Exchange-Organization-AutoForwarded\"=true\n| stats count by sender, recipient"
        ],
        "hunt_steps": [
            "Review inbox rules for all users for hidden or external forwarding.",
            "Correlate header presence with rule creation timestamps.",
            "Search logs for administrative use of mail flow rules."
        ],
        "expected_outcomes": [
            "Identification of persistent email collection rules",
            "Detection of rule abuse not visible in client interface"
        ],
        "false_positive": "Legitimate auto-forwarding rules set by users or admins may appear similar; validation is needed.",
        "clearing_steps": [
            "Delete unauthorized forwarding rules via PowerShell or mail admin panel.",
            "Alert affected users and monitor mailbox for re-rule attempts."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1098", "example": "Account Manipulation"},
            {"tactic": "Credential Access", "technique": "T1556.006", "example": "Email Forwarding for Persistent Access"}
        ],
        "watchlist": [
            "Users with forwarding rules targeting external domains",
            "High volume of mail headers showing auto-forwarding"
        ],
        "enhancements": [
            "Audit rule creation using M365 Unified Audit Logs",
            "Restrict external forwarding at the transport layer unless required"
        ],
        "summary": "Email forwarding rules enable adversaries to maintain silent, persistent access to sensitive email content, often even after a password reset. These rules can be hidden or disguised via APIs.",
        "remediation": "Disable or restrict email forwarding externally. Regularly audit inbox rules and alert on changes.",
        "improvements": "Implement automated rule creation alerts. Use MAPI editors or third-party tools to detect hidden rules across environments."
    }
