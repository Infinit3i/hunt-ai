def get_content():
    return {
        "id": "T1552.008",
        "url_id": "T1552/008",
        "title": "Unsecured Credentials: Chat Messages",
        "description": "Adversaries may directly collect unsecured credentials stored or passed through user communication services.",
        "tags": ["credentials", "chat", "slack", "teams", "jira", "saas", "tokens", "infostealer"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Office Suite, SaaS",
        "tips": [
            "Educate users not to share credentials via messaging platforms.",
            "Apply DLP (Data Loss Prevention) rules to detect and prevent sharing of secrets.",
            "Restrict API scopes for integrations and monitor app access."
        ],
        "data_sources": "Application Log",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Clipboard Data", "location": "Chat applications", "identify": "Copy-paste of tokens, passwords"},
            {"type": "Event Logs", "location": "Slack/Teams/Webhook Access Logs", "identify": "Access from compromised accounts or bots"}
        ],
        "destination_artifacts": [
            {"type": "Application Log", "location": "SaaS Admin Portals", "identify": "Credential-related messages or workflow logs"}
        ],
        "detection_methods": [
            "Use DLP to scan for sensitive keywords or regex patterns in chat content",
            "Monitor for abnormal usage of chat integrations (Slack bots, Jira scripts)",
            "Audit admin logins and API calls retrieving chat content"
        ],
        "apt": [
            "DEV-0537"
        ],
        "spl_query": [
            'index=saas source="chat" message="*password*" OR message="*api_key*" OR message="*token*"\n| stats count by user, app, message',
            'index=saas sourcetype="slack_audit_logs" action="workflow_run" OR action="message_read"\n| stats count by user, action, channel'
        ],
        "hunt_steps": [
            "Search for common credential keywords in message logs if available.",
            "Identify integrations or apps with read access to private channels.",
            "Track API usage or bot activity pulling message history or chat contents."
        ],
        "expected_outcomes": [
            "Detection of credentials sent or stored in chat platforms",
            "Identification of adversarial bot or integration harvesting messages"
        ],
        "false_positive": "Internal automation or development testing may simulate credential sharing. Validate origin and context of each message.",
        "clearing_steps": [
            "Purge chat messages containing sensitive credentials, if supported.",
            "Revoke tokens or passwords exposed via chat logs.",
            "Audit apps and bots with excessive chat permissions."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-credential-theft"
        ],
        "mitre_mapping": [
            {"tactic": "Collection", "technique": "T1114.002", "example": "Reading sensitive messages from SaaS platforms"},
            {"tactic": "Lateral Movement", "technique": "T1021.002", "example": "Using leaked credentials from chat to access RDP or SMB shares"}
        ],
        "watchlist": [
            "api_key", "token", "slack workflow", "teams chat", "integration scripts", "message.history"
        ],
        "enhancements": [
            "Use enterprise-grade DLP across Slack, Teams, and other messaging platforms",
            "Limit bot/integration access and monitor automated API usage"
        ],
        "summary": "Adversaries may gather credentials shared in user chat services like Slack, Teams, Jira, and others to facilitate access and lateral movement.",
        "remediation": "Train users, apply strict content inspection, and audit app-level permissions to prevent credential leakage through chat.",
        "improvements": "Integrate chat platform logs into SIEM and automate regex-based detection of credential patterns in messages.",
        "mitre_version": "16.1"
    }
