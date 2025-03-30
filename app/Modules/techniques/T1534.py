def get_content():
    return {
        "id": "T1534",
        "url_id": "T1534",
        "title": "Internal Spearphishing",
        "description": "After compromising a user account or endpoint within an environment, adversaries may perform internal spearphishing using trusted internal infrastructure (such as corporate email or chat platforms) to trick additional users. Internal spearphishing campaigns can be harder to detect due to their origin from trusted sources and may use techniques like impersonation, malicious attachments, or fake login portals. Payloads may include credential harvesting tools or malware deployment. Adversaries may also use compromised accounts on platforms like Microsoft Teams or Slack to deliver malicious links or requests, further expanding their reach within the network.",
        "tags": ["phishing", "internal", "impersonation", "lateral movement", "chat abuse", "T1534"],
        "tactic": "Lateral Movement",
        "protocol": "",
        "os": "Linux, Office Suite, SaaS, Windows, macOS",
        "tips": [
            "Enable journaling or cloud-integrated scanning of internal email traffic.",
            "Flag internal messages containing known phishing indicators or anomalous patterns.",
            "Monitor for unexpected login locations preceding internal message spamming."
        ],
        "data_sources": "Application Log: Application Log Content, Network Traffic: Network Traffic Content, Network Traffic: Network Traffic Flow",
        "log_sources": [
            {"type": "Application Log", "source": "Email/Chat Logs", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Content", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Flow", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Email Header", "location": "Internal mail server logs", "identify": "Spoofed sender or impersonation indicators"},
            {"type": "Login Logs", "location": "Identity Provider or Email Platform", "identify": "Logins from suspicious IPs before internal messaging activity"},
            {"type": "Attachment Metadata", "location": "Email Gateway", "identify": "Executable or macro-enabled payloads sent to internal users"}
        ],
        "destination_artifacts": [
            {"type": "Click Behavior", "location": "Web Proxy Logs", "identify": "Users visiting phishing portals mimicking SSO login pages"},
            {"type": "Malicious File", "location": "EDR or AV", "identify": "Infection attempts following internal message delivery"},
            {"type": "Chat/Email Trace", "location": "Collaboration Platforms", "identify": "Propagation to internal distribution lists or Teams channels"}
        ],
        "detection_methods": [
            "Monitor internal communication for phishing-like behavior (e.g., credential harvesters, fake login portals).",
            "Use cloud-native security tools or journaling APIs to analyze internal email/chat traffic.",
            "Investigate lateral movement stemming from one compromised identity rapidly messaging multiple users."
        ],
        "apt": [
            "Lazarus Group",  # Known to use internal email hijacking and propagation
            "Gamaredon Group",  # Heavy use of internal spearphishing for spreading malicious documents
            "APT40",  # Internal phishing activity observed in long-term intrusions
            "MuddyWater",  # Leveraged internal communications for further compromise
            "Mandiant-tracked UNC groups",  # Frequently leverage internal trust for lateral spread
            "Operation Muzabi (North Korea-linked)",  # Used internal spearphishing within organizations
        ],
        "spl_query": [
            'index=email_logs sender_domain=yourdomain.com\n| search subject="urgent" OR attachment_type="exe" OR url="http*"\n| stats count by sender, recipient, subject',
            'index=network_proxy_logs\n| search url="*login*" OR url="*credential*"\n| stats count by user, url',
            'index=authentication_logs\n| stats count by user, src_ip\n| where count > threshold AND src_ip="unusual"'
        ],
        "hunt_steps": [
            "Identify internal accounts used shortly after being compromised to send widespread emails.",
            "Trace recipients and follow their authentication or endpoint activity post-message.",
            "Correlate with anomalous login behavior or previous external phishing campaigns."
        ],
        "expected_outcomes": [
            "Identification of lateral phishing campaigns using internal infrastructure.",
            "Detection of credential theft attempts via phishing pages mimicking internal apps.",
            "Correlation of internal spearphishing with upstream access vector (e.g., email compromise)."
        ],
        "false_positive": "Internal users forwarding legitimate external content may appear suspicious depending on heuristics. Validate sender behavior and context.",
        "clearing_steps": [
            "Revoke compromised credentials and session tokens.",
            "Remove phishing content from internal email/chat platforms.",
            "Notify affected users and force password resets if needed."
        ],
        "mitre_mapping": [
            {"tactic": "Lateral Movement", "technique": "T1534", "example": "Use of compromised O365 account to deliver phishing attachments internally"},
            {"tactic": "Credential Access", "technique": "T1056", "example": "Redirecting users to credential harvesting portals via chat/email links"},
            {"tactic": "Initial Access", "technique": "T1566/002", "example": "Spearphishing Link redirected via internal chain forwarding"}
        ],
        "watchlist": [
            "Users sending messages with links to credential harvesting domains",
            "Internal Teams or Slack messages with sudden unusual file sharing",
            "Employees sending messages to large groups they normally do not contact"
        ],
        "enhancements": [
            "Apply role-based access to internal distribution lists.",
            "Enable Microsoft Defender for Office 365 or Google Workspace security rules for internal traffic scanning.",
            "Log and alert on attachment types not commonly used internally (e.g., .vbs, .hta, .js)."
        ],
        "summary": "Internal spearphishing involves adversaries leveraging already-compromised accounts or systems to phish additional users within the same organization. This trusted origin often bypasses traditional external defenses and may use email or collaboration platforms.",
        "remediation": "Investigate origin account compromise, revoke access, and sanitize internal messaging. Notify affected employees and scan impacted systems.",
        "improvements": "Expand internal monitoring to include chat/email traffic, enforce MFA, and reduce lateral movement opportunities.",
        "mitre_version": "16.1"
    }
