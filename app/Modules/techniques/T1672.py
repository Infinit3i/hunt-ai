def get_content():
    return {
        "id": "T1672",
        "url_id": "T1672",
        "title": "Email Spoofing",
        "description": "Adversaries may spoof the sender's email address by modifying email headers to impersonate trusted entities and evade detection.",
        "tags": ["spoofing", "email", "defense evasion", "dmarc", "spf", "dkim"],
        "tactic": "defense-evasion",
        "protocol": "SMTP",
        "os": "Linux, Office Suite, Windows, macOS",
        "tips": [
            "Enforce DMARC with 'reject' or 'quarantine' policy to block spoofed emails.",
            "Use header analysis to flag inconsistencies between sender, return-path, and received domains.",
            "Log and alert on emails failing multiple authentication checks (SPF, DKIM, DMARC)."
        ],
        "data_sources": "Application Log",
        "log_sources": [
            {"type": "Application Log", "source": "O365 or SMTP Gateway", "destination": "Mail Security Platform"}
        ],
        "source_artifacts": [
            {"type": "Email Header", "location": "Message Trace", "identify": "Discrepancies in From and Return-Path headers."}
        ],
        "destination_artifacts": [
            {"type": "Message Trace Log", "location": "Mail Gateway", "identify": "SPF, DKIM, DMARC failures"}
        ],
        "detection_methods": [
            "Check O365 message trace or SMTP logs for failed SPF, DKIM, and DMARC validations.",
            "Detect domain mismatches between envelope and header fields.",
            "Flag high-frequency spoofed sender addresses."
        ],
        "apt": [],
        "spl_query": [
            "sourcetype=\"o365:messageTrace\"| search AuthenticationDetails=\"fail\" OR SPF=\"fail\" OR DKIM=\"fail\" OR DMARC=\"fail\"\n| eval spoof_score=if(SPF=\"fail\", 1, 0) + if(DKIM=\"fail\", 1, 0) + if(DMARC=\"fail\", 1, 0)\n| where spoof_score >= 2\n| table _time, SenderFromAddress, RecipientAddress, Subject, AuthenticationDetails, spoof_score",
            "index=email_logs sourcetype=mail\n| eval from_domain=lower(substr(Sender, strpos(Sender, \"@\")+1))\n| eval return_path_domain=lower(substr(ReturnPath, strpos(ReturnPath, \"@\")+1))\n| where from_domain!=return_path_domain AND isnotnull(ReturnPath)\n| stats count by from_domain, return_path_domain, Subject, _time"
        ],
        "hunt_steps": [
            "Identify domains in your tenant without DMARC enforcement.",
            "Scan inbound mail logs for frequent SPF/DKIM failures.",
            "Correlate spoofed email events with reported phishing attempts."
        ],
        "expected_outcomes": [
            "Detection of spoofed emails attempting to impersonate legitimate senders.",
            "Identification of gaps in email authentication policy enforcement."
        ],
        "false_positive": "Internal routing or email forwarding may trigger SPF failures without malicious intent.",
        "clearing_steps": [
            "Enable DMARC with enforcement.",
            "Deploy SPF/DKIM DNS records across all sending domains.",
            "Educate users to verify sender headers in suspicious emails."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/set-up-spf-in-office-365-to-help-prevent-spoofing?view=o365-worldwide"
        ],
        "mitre_mapping": [
            {"tactic": "defense-evasion", "technique": "T1672", "example": "Email Spoofing"},
            {"tactic": "initial-access", "technique": "T1566.001", "example": "Phishing via spoofed sender"}
        ],
        "watchlist": [
            "Senders failing DMARC policy with high spoof_score",
            "Unexpected external domains spoofing internal identities"
        ],
        "enhancements": [
            "Integrate SPF/DKIM/DMARC with SIEM for correlation.",
            "Leverage anomaly detection on email sender/recipient behavior."
        ],
        "summary": "Email Spoofing involves altering sender headers to impersonate legitimate senders and bypass trust mechanisms, often as part of phishing or social engineering.",
        "remediation": "Implement strict DMARC policies and monitor email authentication failures across your tenant.",
        "improvements": "Automate alerting on SPF/DKIM/DMARC failures and domain mismatches.",
        "mitre_version": "17.0"
    }
