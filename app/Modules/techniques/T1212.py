def get_content():
    return {
        "id": "T1212",
        "url_id": "T1212",
        "title": "Exploitation for Credential Access",
        "description": "Adversaries may exploit software vulnerabilities to obtain access to credentials or bypass authentication mechanisms.",
        "tags": ["Credential Access", "Kerberos", "Replay Attack", "Cloud Exploitation", "Token Abuse"],
        "tactic": "Credential Access",
        "protocol": "Kerberos, HTTP, OAuth, Custom Authentication APIs",
        "os": "Windows, Linux, macOS, Identity Provider",
        "tips": [
            "Monitor unusual authentication patterns involving expired or replayed tokens.",
            "Use anomaly-based alerting on forged Kerberos TGT/TGS usage.",
            "Apply strict validation and lifetime checks on authentication tokens."
        ],
        "data_sources": "Application Log, Process Monitoring, Authentication Logs",
        "log_sources": [
            {"type": "Application Log", "source": "Kerberos, OAuth, Custom Auth", "destination": ""},
            {"type": "Process", "source": "Process Creation", "destination": ""},
            {"type": "User Account", "source": "Authentication Logs", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Ticket Artifacts", "location": "Memory", "identify": "Forged or replayed Kerberos tickets (e.g., MS14-068)"},
            {"type": "Token Dumps", "location": "Cloud token cache", "identify": "Authentication tokens acquired via API abuse"}
        ],
        "destination_artifacts": [
            {"type": "Authentication Events", "location": "Domain Controller / Identity Provider", "identify": "Logon attempts using forged credentials"},
            {"type": "Session Replay", "location": "Traffic logs", "identify": "Duplicate requests with reused tokens or headers"}
        ],
        "detection_methods": [
            "Detect abnormal authentication attempts using forged or expired credentials.",
            "Monitor for Kerberos ticket anomalies including unexpected SIDs or domain mismatches.",
            "Inspect logs for duplicate authentication packets indicative of replay attacks."
        ],
        "apt": ["Storm-0558", "APT28", "Midnight Blizzard"],
        "spl_query": [
            "index=auth_logs (event_type=login OR event_type=kerberos) ticket_flags=\"*forged*\" OR auth_method=\"replay\" \n| stats count by user, src_ip, ticket_id",
            "index=cloud_tokens event_type=auth token_issued_time < token_used_time AND token_validity > threshold \n| table user, token_id, issue_time, use_time"
        ],
        "hunt_steps": [
            "Hunt for Kerberos tickets with abnormally long lifetimes or misaligned user SIDs.",
            "Inspect OAuth logs for unusually long-lived or reused tokens.",
            "Correlate authentication logs with threat intel indicators related to replay or token forgery attacks."
        ],
        "expected_outcomes": [
            "Credential forgery or replay attempt detected and blocked.",
            "Normal authentication behavior confirmed, no signs of exploitation."
        ],
        "false_positive": "Some single sign-on or legacy authentication systems may reuse tokens or cause duplicate authentication events. Review associated systems to confirm intent.",
        "clearing_steps": [
            "Revoke compromised tokens or credentials.",
            "Update vulnerable authentication systems or libraries.",
            "Enforce MFA and reissue user credentials where necessary."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-credential-theft"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1212", "example": "Exploiting MS14-068 to forge Kerberos tickets."},
            {"tactic": "Credential Access", "technique": "T1557.001", "example": "Replay attacks used to bypass token validation."}
        ],
        "watchlist": [
            "High-frequency login attempts from the same user with varying IPs or devices.",
            "OAuth token usage outside issued timeframe.",
            "Reused Kerberos tickets from different sessions or geolocations."
        ],
        "enhancements": [
            "Enable token integrity validation mechanisms.",
            "Use short-lived tokens with strict renewal rules.",
            "Deploy memory protection tools to prevent ticket theft (e.g., Credential Guard, LSASS protection)."
        ],
        "summary": "This technique involves exploiting flaws in authentication mechanisms (such as Kerberos or token-based systems) to access valid credentials or impersonate legitimate users.",
        "remediation": "Patch authentication vulnerabilities, rotate credentials, enforce secure authentication policies, and audit privileged sessions.",
        "improvements": "Implement stricter token lifecycle enforcement, reduce reliance on long-lived tickets, and apply behavioral analytics to detect anomalous logon behavior.",
        "mitre_version": "16.1"
    }
