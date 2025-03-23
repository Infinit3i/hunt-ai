def get_content():
    return {
        "id": "T1114.002",
        "url_id": "T1114/002",
        "title": "Email Collection: Remote Email Collection",
        "description": "Adversaries may target an Exchange server, Office 365, or Google Workspace to collect sensitive information using valid credentials or access tokens.",
        "tags": ["email", "remote collection", "office365", "exchange", "cloud", "imap"],
        "tactic": "Collection",
        "protocol": "IMAP, MAPI, HTTPS",
        "os": "Office Suite, Windows",
        "tips": [
            "Monitor for abnormal login locations, especially for privileged mail accounts.",
            "Look for use of tools like MailSniper or anomalous API access patterns.",
            "Review message audit logs for bulk access patterns in short time windows."
        ],
        "data_sources": "Application Log: Application Log Content, Command: Command Execution, Logon Session: Logon Session Creation, Network Traffic: Network Connection Creation",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": "Application Log"},
            {"type": "Network Traffic", "source": "Network Connection Creation", "destination": "Logon Session"}
        ],
        "source_artifacts": [
            {"type": "IMAP Access", "location": "Office365 or Exchange Online", "identify": "Credential-based mailbox access"},
            {"type": "Token Access", "location": "OAuth / API Calls", "identify": "App impersonation or delegated access"}
        ],
        "destination_artifacts": [
            {"type": "Mailbox Contents", "location": "Cloud Mail Server", "identify": "Exfiltrated emails or attachments"}
        ],
        "detection_methods": [
            "Audit logs for abnormal access times and locations",
            "Detect credential stuffing or brute force login attempts",
            "Correlate message access with known tools or PowerShell modules"
        ],
        "apt": [
            "APT29", "FIN4", "HAFNIUM", "Star Blizzard", "Chimera", "APT1", "Valak", "NICKEL", "Phosphorus", "LightNeuron", "Leafminer", "Seaduke", "APT15", "Exchange Marauder"
        ],
        "spl_query": [
            "index=o365 sourcetype=o365:azuread:signin\n| search ResultType=0 AND AppDisplayName=\"Office 365 Exchange Online\"\n| stats count by UserPrincipalName, ClientIP, Location",
            "index=exchangelogs \"MailSniper\" OR \"Search-Mailbox\" OR \"Get-Mailbox\""
        ],
        "hunt_steps": [
            "Identify users with excessive IMAP/MAPI logins or mailbox access events.",
            "Cross-reference login IPs with geolocation anomalies.",
            "Inspect admin roles for signs of mailbox access or rule manipulation."
        ],
        "expected_outcomes": [
            "Detection of unauthorized mailbox access using valid credentials",
            "Evidence of mass message extraction or mailbox scraping"
        ],
        "false_positive": "Security tools, automated archiving systems, or admin troubleshooting can generate large volumes of mailbox access logs.",
        "clearing_steps": [
            "Revoke stolen credentials or access tokens.",
            "Check for OAuth app impersonation and disable unnecessary delegated access.",
            "Rotate mail service passwords and tokens where applicable."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1556.006", "example": "Cloud Service Access Token Abuse"},
            {"tactic": "Initial Access", "technique": "T1078.004", "example": "Valid Accounts: Cloud Accounts"}
        ],
        "watchlist": [
            "Unusual login attempts from non-corporate networks or unexpected countries",
            "IMAP logins occurring outside business hours or from programmatic sources"
        ],
        "enhancements": [
            "Enable Conditional Access and MFA for all cloud mail services",
            "Log and review MailItemsAccessed and MessageBind events in Microsoft 365"
        ],
        "summary": "Remote email collection involves adversary access to cloud or internal mail platforms like Exchange Online, Office 365, or Google Workspace, often leveraging stolen credentials or tokens.",
        "remediation": "Harden cloud mail configurations, enforce strong authentication methods, and regularly audit mailbox access logs.",
        "improvements": "Enable alerts for abnormal login patterns and excessive message read/download behavior in cloud environments."
    }
