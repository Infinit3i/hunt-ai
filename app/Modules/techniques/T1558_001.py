def get_content():
    return {
        "id": "T1558.001",
        "url_id": "T1558/001",
        "title": "Steal or Forge Kerberos Tickets: Golden Ticket",
        "description": "Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket. Golden tickets enable adversaries to generate authentication material for any account in Active Directory. Using a golden ticket, adversaries are then able to request ticket granting service (TGS) tickets, which enable access to specific resources. Golden tickets require adversaries to interact with the Key Distribution Center (KDC) in order to obtain TGS. The KDC service runs on all domain controllers that are part of an Active Directory domain. KRBTGT is the Kerberos Key Distribution Center (KDC) service account and is responsible for encrypting and signing all Kerberos tickets. The KRBTGT password hash may be obtained using OS Credential Dumping and privileged access to a domain controller.",
        "tags": ["Credential Access", "Golden Ticket", "Kerberos", "KRBTGT", "Active Directory"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Regularly rotate the KRBTGT account password.",
            "Monitor for extended TGT ticket lifetimes.",
            "Enable Kerberos logging to detect unusual ticket requests.",
            "Use managed service accounts to reduce attack surface."
        ],
        "data_sources": "Active Directory: Active Directory Credential Request, Logon Session: Logon Session Metadata",
        "log_sources": [
            {"type": "Active Directory", "source": "", "destination": ""},
            {"type": "Logon Session", "source": "", "destination": ""}
        ],
        "source_artifacts": [],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor malformed or blank fields in Event IDs 4624, 4672, 4634",
            "Detect RC4 encryption usage in TGTs",
            "Look for TGS requests without preceding TGT requests",
            "Alert on TGT lifetimes differing from domain default"
        ],
        "apt": [],
        "spl_query": [
            "index=wineventlog EventCode=4769 OR EventCode=4624 OR EventCode=4672 OR EventCode=4634 | stats count by host, user, TicketEncryptionType, LogonType"
        ],
        "hunt_steps": [
            "Search for abnormal ticket lifetimes in Kerberos logs",
            "Identify user accounts issuing excessive TGS requests",
            "Check for RC4 (0x17) encryption in TGT issuance",
            "Cross-reference ticket creation with credential dumping artifacts"
        ],
        "expected_outcomes": [
            "Reveal forged tickets via unusual encryption types or durations",
            "Uncover privilege escalation paths through golden ticket abuse"
        ],
        "false_positive": "Custom configurations may modify ticket lifetime legitimately. Validate anomalies with AD administrators.",
        "clearing_steps": [
            "Reset KRBTGT password twice to invalidate existing forged tickets",
            "Enable strict TGT lifetime policies",
            "Audit administrative access to domain controllers"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/windows-server/security/kerberos/krbtgt-account-password-reset-procedure",
            "https://attack.mitre.org/techniques/T1558/001"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1558.001", "example": "Adversary uses golden ticket to impersonate domain admin and access resources across AD forest."}
        ],
        "watchlist": [
            "Kerberos TGTs using RC4 encryption",
            "Unusual TGS requests from non-privileged users",
            "Accounts issuing tickets without corresponding logons"
        ],
        "enhancements": [
            "Enable Windows Event ID 4769 and 4624 correlation alerts",
            "Automate TGT duration deviation alerts"
        ],
        "summary": "Golden tickets are forged Kerberos TGTs generated using KRBTGT hashes that grant unrestricted access to domain resources, often used for stealthy, persistent access.",
        "remediation": "Reset KRBTGT password twice, enforce strong log monitoring, and use account tiering to isolate privileged users.",
        "improvements": "Deploy managed identities for services and monitor abnormal Kerberos request patterns via SIEM rules.",
        "mitre_version": "16.1"
    }