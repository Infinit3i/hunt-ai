def get_content():
    return {
        "id": "T1136",
        "url_id": "T1136",
        "title": "Create Account",
        "tactic": "Persistence",
        "data_sources": "Authentication Logs, Windows Event Logs, Linux Audit Logs, Active Directory Logs",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate unauthorized account creation used for persistence or privilege escalation.",
        "scope": "Monitor for unauthorized user or service account creations that may indicate adversary persistence or lateral movement.",
        "threat_model": "Adversaries may create new user accounts to establish persistence, evade detection, or escalate privileges within a system or network.",
        "hypothesis": [
            "Are new accounts being created outside of normal administrative processes?",
            "Are service accounts appearing with unusual privileges or access?",
            "Are there multiple account creation events from the same source in a short period?"
        ],
        "log_sources": [
            {"type": "Authentication Logs", "source": "Windows Event ID 4720 (User Account Creation), Linux /var/log/auth.log"},
            {"type": "Active Directory Logs", "source": "Security Event Logs, LDAP Queries"},
            {"type": "Audit Logs", "source": "Linux AuditD, macOS Unified Logs"}
        ],
        "detection_methods": [
            "Monitor account creation events for non-administrative users.",
            "Detect new accounts added to privileged groups or services.",
            "Identify patterns of multiple account creations from a single source."
        ],
        "spl_query": "index=auth sourcetype=windows EventCode=4720 OR sourcetype=linux:auth | stats count by user, src_ip, _time | sort - count",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1136",
        "hunt_steps": [
            "Run Queries in SIEM: Detect unauthorized account creation attempts.",
            "Correlate with Threat Intelligence Feeds: Validate new account activity against known threat indicators.",
            "Analyze User Behavior: Identify if the new account aligns with normal administrative operations.",
            "Investigate Account Privileges: Determine if excessive privileges were granted to the new account.",
            "Validate & Escalate: If unauthorized account creation is detected → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Unauthorized Account Creation Detected: Disable the account, investigate additional security events, and alert SOC.",
            "No Malicious Activity Found: Improve monitoring for account creation anomalies and enhance user provisioning policies."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1136 (Create Account)", "example": "Adversaries create local or domain accounts for persistence."},
            {"tactic": "Privilege Escalation", "technique": "T1136.001 (Create Local Account)", "example": "Creating a new administrator account to escalate privileges."},
            {"tactic": "Lateral Movement", "technique": "T1136.002 (Create Domain Account)", "example": "Using a new domain account for network movement."}
        ],
        "watchlist": [
            "Monitor creation of new accounts outside of IT-approved processes.",
            "Flag new accounts added to privileged groups (e.g., Administrators, Domain Admins).",
            "Detect multiple accounts created in a short timeframe from the same source."
        ],
        "enhancements": [
            "Implement just-in-time (JIT) access controls to limit persistent account creation.",
            "Enforce multi-factor authentication (MFA) for newly created accounts.",
            "Audit and restrict account creation permissions to designated administrators."
        ],
        "summary": "Monitor for unauthorized account creation as a persistence technique used by adversaries.",
        "remediation": "Disable unauthorized accounts, investigate logs for suspicious activity, and enforce stricter account provisioning policies.",
        "improvements": "Strengthen user management policies, implement automated alerts for account creation, and improve access control mechanisms."
    }
