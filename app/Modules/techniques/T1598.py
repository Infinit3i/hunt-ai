def get_content():
    return {
        "id": "T1598",
        "url_id": "T1598",
        "title": "Phishing for Information",
        "description": "Adversaries may send phishing messages to elicit sensitive information that can be used during targeting. Unlike typical phishing which aims to execute malicious code, this type focuses on tricking victims into disclosing data such as credentials or organizational details through various electronic communication means.",
        "tags": ["phishing", "social engineering", "credential collection", "reconnaissance"],
        "tactic": "Reconnaissance",
        "protocol": "Email, Social Media, Messaging Apps",
        "os": "",
        "tips": [
            "Train employees to scrutinize sender details and avoid disclosing internal information via unsolicited messages.",
            "Deploy email security tools with DKIM, SPF, and DMARC enforcement.",
            "Enable alerts for excessive failed login attempts or profile scraping activities."
        ],
        "data_sources": "Application Log, Network Traffic",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Email Message", "location": "Mailboxes", "identify": "Unusual sender impersonation or urgency"},
            {"type": "Event Logs", "location": "Email Gateway or Proxy", "identify": "Spoofed headers or malformed senders"}
        ],
        "destination_artifacts": [
            {"type": "Form Data", "location": "Attacker-controlled server or email", "identify": "Credentials or internal info submitted"}
        ],
        "detection_methods": [
            "Detect spoofed headers and failed DKIM/SPF validations.",
            "Monitor mass phishing attempts from a single source.",
            "Inspect network traffic for URL redirection or obfuscation patterns."
        ],
        "apt": [
            "APT43", "Moonstone Sleet", "Scattered Spider", "IRON TWILIGHT"
        ],
        "spl_query": [
            'index=email_logs OR index=proxy_logs\n| search subject="*" OR url="*"\n| eval is_suspicious=if(like(sender, "%@%") AND (like(subject, "%urgent%") OR like(body, "%verify%")), "yes", "no")\n| where is_suspicious="yes"\n| stats count by sender, subject, recipient'
        ],
        "hunt_steps": [
            "Identify email campaigns using header anomalies or repeated fake domains.",
            "Trace user clicks on URLs from known phishing domains.",
            "Correlate behavioral changes in users post-phishing message receipt."
        ],
        "expected_outcomes": [
            "Broad detection of phishing campaigns aimed at collecting information.",
            "Visibility into targeted social engineering strategies across departments."
        ],
        "false_positive": "Automated notification systems (e.g., password expiration alerts) may resemble phishing. Validate sender domains and headers.",
        "clearing_steps": [
            "Block identified phishing domains.",
            "Purge suspicious messages across mailboxes.",
            "Report the phishing campaign to affected parties and authorities."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1556", "example": "Collected credentials may be used in password-based attacks"},
            {"tactic": "Initial Access", "technique": "T1566", "example": "Phishing leads to an eventual execution or payload delivery"}
        ],
        "watchlist": [
            "Excessive email sends from unknown domains",
            "Messages using emotion-based keywords like 'urgent', 'update', 'verify'",
            "Failed SPF/DKIM validations on incoming messages"
        ],
        "enhancements": [
            "Deploy inline URL rewriting and detonation capabilities.",
            "Use browser isolation for link previews.",
            "Develop employee simulations for phishing detection training."
        ],
        "summary": "Phishing for information is a form of social engineering where adversaries use electronic communication to collect sensitive details from users. These messages may include urgent requests, impersonate trusted sources, or contain obfuscated links/forms.",
        "remediation": "Analyze scope of campaign exposure, reset credentials if leaked, and enhance filtering rules. Perform retroactive detection for similar lures.",
        "improvements": "Invest in phishing-resistant authentication (e.g., FIDO2), AI-based detection of message tone/content, and enhanced awareness campaigns.",
        "mitre_version": "16.1"
    }
