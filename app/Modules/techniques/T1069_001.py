def get_content():
    return {
        "id": "T1069.001",
        "url_id": "T1069/001",
        "title": "Permission Groups Discovery: Local Groups",
        "description": "Adversaries may attempt to find local system groups and permission settings. The knowledge of local system permission groups can help adversaries determine which groups exist and which users belong to a particular group.",
        "tags": ["discovery", "privilege escalation", "enumeration", "T1069.001"],
        "tactic": "Discovery",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Correlate group enumeration commands with account logins.",
            "Investigate net localgroup activity outside normal IT hours."
        ],
        "data_sources": "Command, Group, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Group", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Command History", "location": "bash history / PowerShell logs", "identify": "Use of net localgroup or equivalent"},
            {"type": "Process List", "location": "Memory", "identify": "Presence of enumeration commands"}
        ],
        "destination_artifacts": [
            {"type": "Event Logs", "location": "Security Log", "identify": "Execution of group enumeration utilities"}
        ],
        "detection_methods": [
            "Monitor net.exe or dscl commands execution",
            "Track PowerShell usage involving group enumeration commands",
            "Detect access to /etc/group on Linux"
        ],
        "apt": ["Turla", "APT34", "Naikon", "OilRig", "Black Basta", "Conti"],
        "spl_query": [
            "index=main sourcetype=Sysmon CommandLine=*net localgroup*",
            "index=main sourcetype=linux_auditd command=groups",
            "index=main source=*powershell* (Get-LocalGroup OR Get-ADGroup)"
        ],
        "hunt_steps": [
            "Search for group enumeration commands across systems",
            "Identify unusual accounts executing group discovery",
            "Map enumeration events to initial access attempts"
        ],
        "expected_outcomes": [
            "Detection of local group discovery for lateral movement planning",
            "Correlated events tied to elevated privilege enumeration"
        ],
        "false_positive": "System administrators may perform group enumeration for routine audits or configuration validation.",
        "clearing_steps": [
            "Delete shell and PowerShell history: `Clear-History`, `rm ~/.bash_history`",
            "Use wevtutil to clear specific event logs: `wevtutil cl Security`"
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1087.001", "example": "User Account Discovery - Local Account queried after group listing"}
        ],
        "watchlist": [
            "Use of net.exe from non-admin accounts",
            "PowerShell invoking Get-LocalGroup on endpoints"
        ],
        "enhancements": [
            "Alert on non-standard users querying local group data",
            "Use EDR tools to track net.exe lineage and ancestry"
        ],
        "summary": "Local group discovery is often used by adversaries to assess privilege levels and plan privilege escalation or lateral movement.",
        "remediation": "Limit access to group enumeration tools to administrators. Monitor and alert on use from unexpected users or systems.",
        "improvements": "Enable script block logging and command line auditing to capture all discovery-related behavior.",
        "mitre_version": "16.1"
    }