def get_content():
    return {
        "id": "T1069",
        "url_id": "T1069",
        "title": "Permission Groups Discovery",
        "description": "Adversaries may attempt to discover group and permission settings to determine user privileges and plan further actions like lateral movement or privilege escalation.",
        "tags": ["discovery", "permission", "group", "enumeration", "T1069"],
        "tactic": "Discovery",
        "protocol": "",
        "os": "Containers, IaaS, Identity Provider, Linux, Office Suite, SaaS, Windows, macOS",
        "tips": [
            "Correlate enumeration activity with account login and network access.",
            "Use RBAC policies in cloud and container environments to limit overprivileged accounts."
        ],
        "data_sources": "Application Log, Command, Group, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Group", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Application Log", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Event Logs", "location": "Security logs", "identify": "Group enumeration commands"},
            {"type": "Command History", "location": "Shell/PowerShell", "identify": "Executed enumeration commands"}
        ],
        "destination_artifacts": [
            {"type": "Logon Session", "location": "Windows Event Logs", "identify": "Linked user context"},
            {"type": "Network Connections", "location": "Sysmon", "identify": "LDAP or API-based group queries"}
        ],
        "detection_methods": [
            "Monitor for use of commands like net group, whoami /groups, id, and dsquery",
            "Look for PowerShell or WMI scripts accessing group metadata"
        ],
        "apt": ["TA505", "APT41", "Buckeye", "FIN13"],
        "spl_query": [
            "index=main sourcetype=WinEventLog:Security (EventCode=4688 AND (CommandLine=*net group* OR CommandLine=*whoami* OR CommandLine=*dsquery*))",
            "index=main source=*powershell* (Get-ADGroupMember OR Get-ADGroup)"
        ],
        "hunt_steps": [
            "Identify endpoints executing group-related commands",
            "Trace back to initiating accounts and sessions",
            "Check for unusual timing, source IPs, or service accounts performing queries"
        ],
        "expected_outcomes": [
            "Detection of enumeration of domain groups or local admin groups",
            "Correlation to possible privilege escalation planning"
        ],
        "false_positive": "System administrators may regularly query group membership during account management.",
        "clearing_steps": [
            "Clear PowerShell and shell history files",
            "Delete logs using `wevtutil cl Security` (Windows) or `journalctl --vacuum-time=1s` (Linux)",
            "Remove temporary scripts used to gather group info"
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1087", "example": "Account Discovery follows group enumeration to target specific users"}
        ],
        "watchlist": [
            "Repeated group queries from newly joined endpoints",
            "Use of discovery commands by non-privileged users"
        ],
        "enhancements": [
            "Implement Just Enough Admin (JEA) for PowerShell",
            "Log and restrict dsquery usage in enterprise environments"
        ],
        "summary": "Permission Groups Discovery helps adversaries identify key user roles and access paths within a target environment, often serving as a precursor to lateral movement or privilege escalation.",
        "remediation": "Restrict access to group enumeration utilities. Audit accounts and roles with discovery privileges. Use group policies to limit exposure.",
        "improvements": "Use central logging for AD queries. Implement behavioral alerting on group lookup frequency per account.",
        "mitre_version": "16.1"
    }
