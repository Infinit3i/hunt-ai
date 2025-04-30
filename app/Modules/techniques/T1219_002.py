def get_content():
    return {
        "id": "T1219.002",
        "url_id": "T1219/002",
        "title": "Remote Desktop Software",
        "description": "An adversary may use legitimate desktop support software to establish an interactive command and control channel to target systems within networks.",
        "tags": ["c2", "teamviewer", "anydesk", "logmein", "screenconnect", "rmm", "remote desktop", "interactive access"],
        "tactic": "command-and-control",
        "protocol": "TCP, HTTP, HTTPS",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Monitor use of common RMM tools in unexpected environments.",
            "Block installations of unapproved remote desktop software via application control.",
            "Inspect unusual outbound traffic to known remote desktop domains."
        ],
        "data_sources": "Network Traffic, Process",
        "log_sources": [
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Event Logs", "location": "Sysmon Operational", "identify": "Execution of remote desktop tools such as AnyDesk or TeamViewer"},
            {"type": "Process List", "location": "RAM", "identify": "Presence of active RMM tools unexpectedly"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Firewall Logs", "identify": "Outbound connection to *.anydesk.com or *.teamviewer.com"}
        ],
        "detection_methods": [
            "Inspect process creation logs for execution of known remote desktop software.",
            "Track outgoing traffic on ports commonly used by remote desktop tools.",
            "Correlate with threat intel for abuse of RMMs by threat actors."
        ],
        "apt": ["Kimsuky", "Evilnum", "RTM", "Storm-1811", "Mustang Panda", "Thrip"],
        "spl_query": [
            "sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=3(DestinationHostname IN (\".teamviewer.com\", \".anydesk.com\", \".logmein.com\", \".screenconnect.com\") OR DestinationPort IN (5938, 7070, 7071, 443))\n| stats count by Image, DestinationIp, DestinationPort, CommandLine, host, _time\n| sort -_time",
            "sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational(Image=\"\\TeamViewer.exe\" OR Image=\"\\AnyDesk.exe\" OR Image=\"\\Ammyy_Admin.exe\" OR Image=\"\\connectwisecontrol.client.exe\")\n| stats count by Image, ParentImage, CommandLine, user, host, _time\n| sort -_time"
        ],
        "hunt_steps": [
            "Identify all endpoints with active remote desktop or RMM software running.",
            "Investigate associated connections to known vendor IP ranges.",
            "Review installation logs or delivery methods."
        ],
        "expected_outcomes": [
            "Detection of adversary-controlled remote access software being used as a C2 channel."
        ],
        "false_positive": "IT administrators and support teams may use these tools legitimately. Validate by user role and activity context.",
        "clearing_steps": [
            "Uninstall unauthorized remote access applications.",
            "Revoke persistent agent keys or cloud accounts.",
            "Terminate active remote sessions and inspect registry/services for persistence."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "command-and-control", "technique": "T1219", "example": "Remote Access Tools"},
            {"tactic": "execution", "technique": "T1204.002", "example": "Malicious File"}
        ],
        "watchlist": [
            "AnyDesk or TeamViewer processes on servers or sensitive endpoints",
            "Outbound RDP-like traffic from user devices to cloud relays"
        ],
        "enhancements": [
            "Block installer hashes for known RMM software in non-admin environments.",
            "Alert on remote access tools running outside business hours."
        ],
        "summary": "Remote Desktop Software offers adversaries covert and interactive access to systems, often exploiting legitimate tools like TeamViewer or AnyDesk to avoid detection.",
        "remediation": "Restrict installation and usage of remote access tools to authorized IT personnel only, and log all activity.",
        "improvements": "Integrate remote access tool detection with behavioral baselining and enforce least privilege execution.",
        "mitre_version": "17.0"
    }
