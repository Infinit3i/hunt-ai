def get_content():
    return {
        "id": "T1098",
        "url_id": "T1098",
        "title": "Account Manipulation",
        "tactic": "Persistence",
        "data_sources": "Authentication Logs, Windows Event, Sysmon, Active Directory, EDR",
        "protocol": "LDAP, Kerberos, RDP, SMB, SSH",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate unauthorized account modifications, privilege escalations, and malicious user account activities.",
        "scope": "Monitor user account modifications, privilege assignments, and unauthorized login attempts.",
        "threat_model": "Adversaries may manipulate accounts to establish persistence, escalate privileges, or evade detection.",
        "hypothesis": [
            "Are there unexpected privilege escalations or role changes in user accounts?",
            "Are inactive or disabled accounts being reactivated?",
            "Are new user accounts being created by non-administrators?"
        ],
        "log_sources": [
            {"type": "Authentication Logs", "source": "Windows Security Logs (Event ID 4720, 4722, 4724, 4738, 4740), Linux auth.log"},
            {"type": "Active Directory Logs", "source": "Domain Controller Event Logs, Azure AD Logs"},
            {"type": "EDR Logs", "source": "CrowdStrike, Defender ATP, Carbon Black"}
        ],
        "detection_methods": [
            "Monitor privilege escalations and user role changes.",
            "Detect reactivation of previously disabled or inactive accounts.",
            "Identify account creation or modification outside of normal business hours."
        ],
        "spl_query": "index=auth_logs (EventCode=4720 OR EventCode=4724 OR EventCode=4738 OR EventCode=4740) | stats count by Account_Name, EventCode, _time | sort - count",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1098",
        "hunt_steps": [
            "Run Queries in SIEM: Identify unauthorized user account modifications.",
            "Correlate with Threat Intelligence Feeds: Check suspicious accounts against known indicators.",
            "Analyze Account Behavior: Review user activity pre- and post-modification.",
            "Investigate Authentication Logs: Identify login attempts associated with manipulated accounts.",
            "Validate & Escalate: Escalate if unauthorized changes are detected."
        ],
        "expected_outcomes": [
            "Account Manipulation Detected: Investigate unauthorized changes and revoke access.",
            "No Malicious Activity Found: Improve user account monitoring and authentication policies."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1098 (Account Manipulation)", "example": "Adversary modifies account privileges."},
            {"tactic": "Privilege Escalation", "technique": "T1078 (Valid Accounts)", "example": "Adversary gains higher privileges through account manipulation."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Adversary deletes logs to hide account modifications."}
        ],
        "watchlist": [
            "Monitor unexpected privilege changes.",
            "Track user account reactivations and modifications.",
            "Detect new account creations by non-administrators."
        ],
        "enhancements": [
            "Enforce Multi-Factor Authentication (MFA) for privileged accounts.",
            "Implement strict role-based access controls (RBAC).",
            "Enable logging and alerting on all account modifications."
        ],
        "summary": "Document all unauthorized account changes and potential privilege escalations.",
        "remediation": "Revert unauthorized account modifications and strengthen access policies.",
        "improvements": "Enhance auditing and monitoring of privileged user actions."
    }
