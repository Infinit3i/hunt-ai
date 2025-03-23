def get_content():
    return {
        "id": "T1114",
        "url_id": "T1114",
        "title": "Email Collection",
        "description": "Adversaries may target user email to collect sensitive information. Emails may contain sensitive data, including trade secrets or personal information, that can prove valuable to adversaries.",
        "tags": ["email", "collection", "exfiltration", "autoforwarding", "exchange"],
        "tactic": "Collection",
        "protocol": "",
        "os": "Linux, Office Suite, Windows, macOS",
        "tips": [
            "Monitor processes and command-line arguments accessing local email files.",
            "Watch for unexpected access to email servers using unusual user agents.",
            "Detect use of auto-forwarding rules using email headers like X-MS-Exchange-Organization-AutoForwarded."
        ],
        "data_sources": "Application Log: Application Log Content, Command: Command Execution, File: File Access, Logon Session: Logon Session Creation, Network Traffic: Network Connection Creation",
        "log_sources": [
            {"type": "File", "source": "File Access", "destination": "Application Log"},
            {"type": "Command", "source": "Command Execution", "destination": "Logon Session"},
            {"type": "Network Traffic", "source": "Network Connection Creation", "destination": "Application Log"}
        ],
        "source_artifacts": [
            {"type": "Email Client", "location": "Local Filesystem", "identify": "PST/OST/EML/MSG files"}
        ],
        "destination_artifacts": [
            {"type": "Auto-Forwarded Emails", "location": "Exchange Headers", "identify": "X-MS-Exchange-Organization-AutoForwarded"}
        ],
        "detection_methods": [
            "Monitor for auto-forwarding rule creation",
            "Analyze email header artifacts for silent forwarding",
            "Track abnormal volumes of forwarded messages"
        ],
        "apt": [
            "Emotet", "Charming Kitten", "Scattered Spider", "GRU29155", "Cadet Blizzard", "IcedID"
        ],
        "spl_query": [
            "index=exchange_logs X-MS-Exchange-Organization-AutoForwarded=true\n| stats count by sender, recipient, subject",
            "index=email_logs \"forwardingSMTPAddress\"\n| stats count by user"
        ],
        "hunt_steps": [
            "Analyze user mailbox rules for unauthorized forwarding entries.",
            "Correlate forwarded messages with login sessions to detect anomalies.",
            "Hunt for PowerShell/WMI commands accessing email-related paths."
        ],
        "expected_outcomes": [
            "Detection of stealth email forwarding rules",
            "Evidence of sensitive data collection via email"
        ],
        "false_positive": "Admins may configure forwarding rules legitimately; certain applications (e.g., ticketing systems) might use similar mechanisms.",
        "clearing_steps": [
            "Remove unauthorized email forwarding rules from mailboxes or admin policies.",
            "Revoke compromised credentials and audit email access logs."
        ],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1048", "example": "Exfiltration Over Alternative Protocol"},
            {"tactic": "Persistence", "technique": "T1098", "example": "Account Manipulation"}
        ],
        "watchlist": [
            "Auto-forwarded emails with no matching manual forward",
            "Usage of PowerShell scripts accessing Outlook API"
        ],
        "enhancements": [
            "Enable advanced logging for Exchange Online and Outlook clients.",
            "Implement anomaly detection for new forwarding rule creation."
        ],
        "summary": "Email Collection enables adversaries to harvest internal communication and sensitive data, often by abusing forwarding rules or direct file access.",
        "remediation": "Restrict rule creation privileges, enable alerts for forwarding behavior, and use MFA to protect mailbox access.",
        "improvements": "Deploy DLP (Data Loss Prevention) tools to detect sensitive content exfiltration via email and alert on anomalous mailbox activities."
    }
