def get_content():
    return {
        "id": "T1556.006",
        "url_id": "T1556/006",
        "title": "Modify Authentication Process: Multi-Factor Authentication",
        "description": "Adversaries may disable or modify multi-factor authentication (MFA) mechanisms to enable persistent access to compromised accounts. Once adversaries have gained access to a network by either compromising an account lacking MFA or by employing an MFA bypass method such as Multi-Factor Authentication Request Generation, adversaries may leverage their access to modify or completely disable MFA defenses.",
        "tags": ["Credential Access", "Defense Evasion", "Persistence", "MFA", "Cloud", "Identity Provider"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "IaaS, Identity Provider, Linux, Office Suite, SaaS, Windows, macOS",
        "tips": [
            "Audit conditional access policies for overbroad exclusions.",
            "Monitor for newly registered or modified MFA methods.",
            "Alert on MFA endpoint resolution redirections (e.g., hosts file modifications).",
            "Review logs for mass MFA disablement or fail-open events."
        ],
        "data_sources": "Active Directory: Active Directory Object Modification, Application Log: Application Log Content, Logon Session: Logon Session Creation, User Account: User Account Authentication, User Account: User Account Modification",
        "log_sources": [
            {"type": "Active Directory", "source": "", "destination": ""},
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Logon Session", "source": "", "destination": ""},
            {"type": "User Account", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Hosts File", "location": "C:\\Windows\\System32\\drivers\\etc\\hosts", "identify": "MFA server redirection"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Audit logging for MFA method changes",
            "DNS and hosts file integrity monitoring",
            "Identity provider configuration change monitoring",
            "Detection of MFA bypass techniques (e.g., fail-open)"
        ],
        "apt": [
            "APT42",
            "Scattered Spider"
        ],
        "spl_query": [
            "`index=auth_logs event=mfa_change OR event=mfa_remove | stats count by user, action, timestamp`",
            "`index=os_logs sourcetype=windows_hosts_modifications path=\\etc\\hosts | search MFA`"
        ],
        "hunt_steps": [
            "Search for MFA policy exclusions in Azure/Okta",
            "Review logs for mass MFA disable events",
            "Identify changes in MFA registration patterns",
            "Look for hosts file modifications targeting MFA servers"
        ],
        "expected_outcomes": [
            "Detection of unauthorized MFA disablement",
            "Visibility into MFA abuse for persistence"
        ],
        "false_positive": "Admin-permitted exclusions or MFA test configurations may appear similar. Cross-reference user context and changes.",
        "clearing_steps": [
            "Restore MFA policy configuration and re-register MFA methods",
            "Revert unauthorized changes to identity provider and hosts file",
            "Force sign-out and reset tokens"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-credential-theft"
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1556.006", "example": "Disabling MFA by modifying Azure Conditional Access policy exclusions."}
        ],
        "watchlist": [
            "Users with repeated MFA method changes",
            "Hosts with modified DNS/hosts entries targeting MFA endpoints",
            "Logins occurring post MFA deactivation"
        ],
        "enhancements": [
            "Alert when MFA is disabled without a ticket reference",
            "Baseline normal MFA configuration per department or role"
        ],
        "summary": "This technique targets the integrity and enforcement of MFA controls, leveraging identity and access misconfigurations or endpoint manipulations to allow unauthorized access.",
        "remediation": "Regularly audit MFA settings, enforce strict change controls, and validate integrity of MFA infrastructure including identity provider configurations and endpoint DNS resolution paths.",
        "improvements": "Implement just-in-time MFA validation alerts and endpoint monitoring for MFA redirection attacks (e.g., /etc/hosts or DNS hijackings).",
        "mitre_version": "16.1"
    }