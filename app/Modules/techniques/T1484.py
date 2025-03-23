def get_content():
    return {
        "id": "T1484",
        "url_id": "T1484",
        "title": "Domain or Tenant Policy Modification",
        "description": "Adversaries may modify the configuration settings of a domain or identity tenant to evade defenses and/or escalate privileges in centrally managed environments.",
        "tags": ["t1484", "domain or tenant policy modification", "defense evasion", "privilege escalation", "windows", "identity provider"],
        "tactic": "Defense Evasion, Privilege Escalation",
        "protocol": "Active Directory, Identity Provider",
        "os": "Windows",
        "tips": [
            "Audit Group Policy Object (GPO) changes regularly to detect unauthorized modifications.",
            "Use security filtering to limit GPO access to only necessary users/groups.",
            "Implement alerts for federation trust or authentication setting modifications."
        ],
        "data_sources": "Active Directory: Active Directory Object Creation, Active Directory: Active Directory Object Deletion, Active Directory: Active Directory Object Modification, Application Log: Application Log Content, Command: Command Execution",
        "log_sources": [
            {"type": "Active Directory", "source": "GPO changes", "destination": "SIEM"},
            {"type": "Application Log", "source": "Federation/Trust Events", "destination": "Monitoring Platform"}
        ],
        "source_artifacts": [
            {"type": "Event Log", "location": "Event ID 5136, 5137, 5138, 5139, 5141", "identify": "GPO Modification Tracking"},
            {"type": "Event Log", "location": "Azure AD Audit Logs", "identify": "Federation Change Detection"}
        ],
        "destination_artifacts": [
            {"type": "Active Directory Object", "location": "GPO Settings", "identify": "Group Policy Modification"},
            {"type": "Tenant Settings", "location": "Federation Trust Config", "identify": "Federated Identity Abuse"}
        ],
        "detection_methods": [
            "Monitor Windows Event IDs for AD object changes (e.g. 5136-5141).",
            "Monitor Azure AD for changes to domain federation/authentication settings.",
            "Track command-line tools modifying domain settings."
        ],
        "apt": [],
        "spl_query": [
            "index=wineventlog EventCode IN (5136,5137,5138,5139,5141)",
            "index=azuread_logs ActionType=\"Set federation settings on domain\" OR ActionType=\"Set domain authentication\""
        ],
        "hunt_steps": [
            "Review recent GPO changes across the domain and validate changes.",
            "Check Azure AD federation and identity provider settings for unauthorized changes."
        ],
        "expected_outcomes": [
            "Detection of malicious changes to domain policy or trust relationships.",
            "Prevention of attacker access via modified authentication methods."
        ],
        "false_positive": "Legitimate changes by domain administrators may trigger these logs. Always correlate with change management processes.",
        "clearing_steps": [
            "Revert unauthorized GPO or trust configuration changes.",
            "Remove malicious federated identity providers."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1562", "example": "Evading monitoring by reverting changes after execution"},
            {"tactic": "Privilege Escalation", "technique": "T1078", "example": "Establishing unauthorized access via federation abuse"}
        ],
        "watchlist": [
            "Monitor Azure AD for trust changes.",
            "Alert on creation of new GPOs with auto-run scheduled tasks."
        ],
        "enhancements": [
            "Use GPO change logging and backup automation.",
            "Implement strict federation trust validation workflows."
        ],
        "summary": "Adversaries may alter domain or identity tenant policy settings to maintain persistence, escalate privileges, or evade detection.",
        "remediation": "Reinforce role-based access controls and implement just-in-time administration policies.",
        "improvements": "Adopt federation change monitoring solutions and ensure GPO settings are audited and version-controlled."
    }
