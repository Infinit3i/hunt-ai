def get_content():
    return {
        "id": "T1069.002",
        "url_id": "T1069/002",
        "title": "Permission Groups Discovery: Domain Groups",
        "description": "Adversaries may attempt to find domain-level groups and permission settings. The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group.",
        "tags": ["discovery", "domain", "privilege escalation", "T1069.002"],
        "tactic": "Discovery",
        "protocol": "LDAP, SMB, RPC",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Look for domain group enumeration shortly after initial access.",
            "Monitor usage of LDAP or net commands targeting domain group information."
        ],
        "data_sources": "Command, Group, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Group", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Command History", "location": "bash history / PowerShell logs", "identify": "Use of net group /domain or ldapsearch"},
            {"type": "Event Logs", "location": "Security Log", "identify": "Execution of domain group enumeration commands"}
        ],
        "destination_artifacts": [
            {"type": "Event Logs", "location": "Domain Controller Logs", "identify": "Remote enumeration of domain groups"}
        ],
        "detection_methods": [
            "Monitor net.exe usage with /domain flag",
            "Track ldapsearch or dsquery access to group metadata",
            "Alert on repeated enumeration of domain groups from non-domain joined hosts"
        ],
        "apt": ["APT34", "FIN6", "FIN7", "APT41", "Turla", "Ryuk", "SILENTTRINITY"],
        "spl_query": [
            "index=main sourcetype=Sysmon CommandLine=*net group /domain*",
            "index=main sourcetype=windows_security EventCode=4688 NewProcessName=*dsquery*",
            "index=main sourcetype=linux_auditd command=ldapsearch"
        ],
        "hunt_steps": [
            "Identify all hosts issuing domain group discovery commands",
            "Track correlation between domain enumeration and privilege escalation or lateral movement",
            "Flag commands targeting domain groups from endpoints without domain admin tools"
        ],
        "expected_outcomes": [
            "Detection of domain-level group discovery for privilege mapping",
            "Correlation to user enumeration and attack staging behavior"
        ],
        "false_positive": "Legitimate IT operations or audit tools may query domain group memberships routinely.",
        "clearing_steps": [
            "Clear PowerShell history with `Clear-History` and bash with `rm ~/.bash_history`",
            "Delete Event Logs with `wevtutil cl Security` on Windows",
            "Purge LDAP query logs on Linux domain tools"
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1087.002", "example": "User Account Discovery - Domain Account queried after domain group discovery"}
        ],
        "watchlist": [
            "Execution of domain group queries outside business hours",
            "Enumeration from non-domain joined or misaligned hosts"
        ],
        "enhancements": [
            "Implement detection rules for domain group discovery commands",
            "Log all domain queries via LDAP or PowerShell AD modules"
        ],
        "summary": "Domain group discovery helps adversaries identify high-value targets and permission relationships for lateral movement or privilege escalation.",
        "remediation": "Restrict access to domain enumeration tools. Monitor for misuse and apply least privilege to users.",
        "improvements": "Enhance logging on domain controllers and deploy anomaly-based detections for group enumeration behavior.",
        "mitre_version": "16.1"
    }
