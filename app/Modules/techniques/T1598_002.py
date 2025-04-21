def get_content():
    return {
        "id": "T1598.002",
        "url_id": "T1598/002",
        "title": "Phishing for Information: Spearphishing Attachment",
        "description": "Adversaries may send spearphishing messages with a malicious attachment to elicit sensitive information that can be used during targeting. These attachments are typically designed to appear legitimate, requesting the recipient to complete and return them, often under the guise of business communication.",
        "tags": ["spearphishing", "malicious attachment", "reconnaissance", "data collection"],
        "tactic": "Reconnaissance",
        "protocol": "SMTP/Email",
        "os": "",
        "tips": [
            "Scan incoming attachments with sandbox detonation tools.",
            "Educate users to verify the source and intent of attachments before interacting.",
            "Establish a policy to block certain attachment types (e.g., .hta, .js, .exe) in emails."
        ],
        "data_sources": "Application Log, Network Traffic",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Email Message", "location": "Inbox", "identify": "Suspicious sender with unusual attachment"},
            {"type": "File Access Times (MACB Timestamps)", "location": "Local User System", "identify": "Attachment opened outside business hours"}
        ],
        "destination_artifacts": [
            {"type": "Form Data", "location": "Email Reply or Uploaded via URL", "identify": "User-completed document with sensitive input"}
        ],
        "detection_methods": [
            "Monitor email gateways for suspicious attachment file types.",
            "Use content inspection to analyze document macros or embedded scripts.",
            "Correlate form-filled documents with external email replies."
        ],
        "apt": [
            "Star Blizzard", "Sidewinder", "COLDRIVER", "SideCopy"
        ],
        "spl_query": [
            'index=email_logs\n| search attachment_type="doc" OR attachment_type="xls" OR attachment_type="pdf"\n| eval is_suspicious=if(like(subject, "%urgent%") OR like(body, "%fill out%"), "yes", "no")\n| where is_suspicious="yes"\n| stats count by sender, recipient, attachment_name'
        ],
        "hunt_steps": [
            "Review mail server logs for attachments sent from external domains.",
            "Hunt for recently downloaded or opened attachments in user workstations.",
            "Identify document files with embedded macros or content from unknown authors."
        ],
        "expected_outcomes": [
            "Detection of phishing attempts using document-based social engineering.",
            "Identification of users who opened or replied with completed forms."
        ],
        "false_positive": "Legitimate business operations may include similar file exchanges. Cross-reference sender and content context before flagging.",
        "clearing_steps": [
            "Purge suspicious messages from inboxes using EDR or mail admin console.",
            "Educate affected users on safe attachment practices.",
            "Quarantine any returned documents and analyze for data exposure."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Collection", "technique": "T1114", "example": "User submits data back to the attacker via returned document"},
            {"tactic": "Initial Access", "technique": "T1566.001", "example": "Adversary gains access via malicious document lure"}
        ],
        "watchlist": [
            "Frequent .doc/.xls attachments from unknown senders",
            "Keywords in email body like 'fill out', 'update form', 'verify info'",
            "Returned files with recently modified metadata"
        ],
        "enhancements": [
            "Implement DLP solutions to monitor sensitive content in returned emails.",
            "Enable attachment sandboxing before delivery to end-users.",
            "Enforce metadata tagging for incoming attachments."
        ],
        "summary": "Spearphishing via attachments is a social engineering tactic where adversaries embed malicious content in documents or request sensitive data to be filled out and returned. These attacks often use urgency and impersonation to convince recipients.",
        "remediation": "Remove phishing emails and attachments from mailboxes, review user response, and disable any accounts or reset credentials if data was submitted.",
        "improvements": "Develop rules to inspect returned documents for filled-in fields, detect repeated delivery of attachment-based phishing lures, and simulate these threats internally for training.",
        "mitre_version": "16.1"
    }
