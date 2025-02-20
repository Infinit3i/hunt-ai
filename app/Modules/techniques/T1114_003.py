def get_content():
    return {
        "id": "T1114.003",
        "url_id": "T1114/003",
        "title": "Email Forwarding Rule",
        "tactic": "Collection, Persistence",
        "data_sources": "Email Logs, Windows Event Logs, Registry, File System",
        "protocol": "SMTP, IMAP, Exchange",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries may create email forwarding rules to automatically collect and exfiltrate email communications.",
        "scope": "Monitor email rules and configuration changes for unauthorized forwarding mechanisms.",
        "threat_model": "Attackers can persist in an environment by setting email forwarding rules to send copies of inbound or outbound emails to an external account.",
        "hypothesis": [
            "Are new email forwarding rules being created unexpectedly?",
            "Are existing rules being modified to exfiltrate data?",
            "Are attackers using auto-forwarding to bypass DLP controls?"
        ],
        "tips": [
            "Monitor changes to email forwarding rules within Exchange, O365, and other mail servers.",
            "Analyze event logs for unusual modifications to mail client settings.",
            "Check for rules that forward all emails to external domains."
        ],
        "log_sources": [
            {"type": "Email Logs", "source": "Exchange Message Tracking Logs, O365 Audit Logs"},
            {"type": "Windows Event Logs", "source": "Security.evtx, Application.evtx"},
            {"type": "Registry", "source": "HKCU\\Software\\Microsoft\\Office\\Outlook\\Rules"}
        ],
        "source_artifacts": [
            {"type": "Mail Client Configuration", "location": "Outlook Rules, OWA Rules", "identify": "Unauthorized forwarding rules"}
        ],
        "destination_artifacts": [
            {"type": "Email Logs", "location": "Mail Server Logs", "identify": "Suspicious auto-forwarding activity"}
        ],
        "detection_methods": [
            "Monitor for creation of new auto-forwarding rules in email servers.",
            "Detect excessive emails being forwarded to external accounts.",
            "Analyze email headers for signs of unauthorized forwarding."
        ],
        "apt": ["G0032", "G0096"],
        "spl_query": [
            "index=email sourcetype=exchange_logs forwarding_rule=* | table sender, recipient, rule_name"
        ],
        "hunt_steps": [
            "Investigate new forwarding rules added in the last 30 days.",
            "Check email logs for anomalous forwarding patterns.",
            "Correlate rule creation with known threat actor TTPs."
        ],
        "expected_outcomes": [
            "Unauthorized forwarding rules detected and removed.",
            "No suspicious activity found, improving baseline detection."
        ],
        "false_positive": "Users may create forwarding rules for legitimate workflow automation.",
        "clearing_steps": [
            "Disable and remove unauthorized forwarding rules in mail clients.",
            "Investigate and revoke compromised accounts if unauthorized forwarding is found."
        ],
        "mitre_mapping": [
            {"tactic": "Collection", "technique": "T1114.003 (Email Forwarding Rule)", "example": "Adversaries may use email rules to exfiltrate sensitive communications."}
        ],
        "watchlist": [
            "Monitor for newly created forwarding rules targeting external domains.",
            "Detect high-volume email forwarding behavior."
        ],
        "enhancements": [
            "Implement email forwarding restrictions in Exchange/O365 policies.",
            "Enforce MFA for all email accounts to reduce unauthorized access."
        ],
        "summary": "Attackers may leverage email forwarding rules to persist in an environment and exfiltrate sensitive email communications.",
        "remediation": "Review and disable unauthorized forwarding rules, implement security awareness training.",
        "improvements": "Enhance monitoring for email rule modifications and restrict external email forwarding."
    }
