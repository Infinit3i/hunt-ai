def get_content():
    return {
        "id": "T1585.002",
        "url_id": "T1585/002",
        "title": "Establish Accounts: Email Accounts",
        "description": "Adversaries may create email accounts that can be used during targeting. Adversaries can use accounts created with email providers to further their operations, such as leveraging them to conduct Phishing for Information or Phishing. Establishing email accounts may also allow adversaries to abuse free services – such as trial periods – to Acquire Infrastructure for follow-on purposes.",
        "tags": ["phishing", "infrastructure", "persona", "resource development"],
        "tactic": "Resource Development",
        "protocol": "",
        "os": "PRE",
        "tips": [
            "Monitor registration patterns tied to free or disposable email services",
            "Analyze sender reputation and domain age in inbound emails",
            "Correlate accounts tied to phishing campaigns"
        ],
        "data_sources": "",
        "log_sources": [],
        "source_artifacts": [
            {"type": "Email Account Creation", "location": "Email Provider", "identify": "New account using disposable email domains"}
        ],
        "destination_artifacts": [
            {"type": "Email Delivery", "location": "Inbox or Mail Gateway", "identify": "Suspicious sender or domain"}
        ],
        "detection_methods": [
            "Email reputation analysis",
            "Threat intel feed correlation with known throwaway domains",
            "Detection of emails sent from newly registered domains"
        ],
        "apt": [],
        "spl_query": [
            'index=email OR index=proxy\n| search sender_domain IN ("protonmail.com", "tutanota.com", "tempmail.com", "mailinator.com")\n| stats count by sender_email, recipient_email, sender_domain'
        ],
        "hunt_steps": [
            "Track recently registered domains used for email activity",
            "Monitor email gateways for traffic from suspicious sender domains",
            "Analyze headers for disposable service indicators"
        ],
        "expected_outcomes": [
            "Detection of newly created or disposable email accounts used in attacks",
            "Prevented phishing attempts or infrastructure registration from malicious emails"
        ],
        "false_positive": "Legitimate users utilizing privacy-focused email services such as ProtonMail or Tutanota.",
        "clearing_steps": [
            "Block domains used for disposable emails in email gateways",
            "Add risky email domains to watchlists and policy filters",
            "Suspend access for accounts interacting with suspicious email senders"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1566", "example": "Phishing emails sent from attacker-created email account"},
            {"tactic": "Resource Development", "technique": "T1583/001", "example": "Registering domains using attacker-created email addresses"}
        ],
        "watchlist": [
            "High frequency of newly created email senders",
            "Inbound messages with low reputation or unverifiable DKIM/SPF"
        ],
        "enhancements": [
            "Integrate domain reputation with spam filter policies",
            "Use DLP rules to restrict sensitive data sent to unknown or new external addresses"
        ],
        "summary": "Adversaries may use newly created or disposable email accounts to stage phishing attacks, register infrastructure, and build personas to support follow-on operations.",
        "remediation": "Enforce stronger anti-spam filtering, monitor for email abuse indicators, and integrate domain age and type into detection logic.",
        "improvements": "Adopt behavioral analytics on email usage patterns and automate sandbox analysis of suspicious emails.",
        "mitre_version": "16.1"
    }
