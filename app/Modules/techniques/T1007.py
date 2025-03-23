def get_content():
    return {
        "id": "T1007",
        "url_id": "T1007",
        "title": "System Service Discovery",
        "description": "Adversaries may attempt to discover information about system services using built-in utilities or commands.",
        "tags": ["system service", "discovery", "sc query", "systemctl", "net start", "tasklist /svc"],
        "tactic": "Discovery",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor usage of service discovery commands like `sc query`, `systemctl`, or `net start`",
            "Correlate with other discovery activity to identify early-stage intrusions",
            "Flag access to service management commands from unknown or suspicious processes"
        ],
        "data_sources": "Command, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Shell History", "location": "~/.bash_history", "identify": "Command execution history"},
            {"type": "Sysmon Logs", "location": "Event ID 1", "identify": "Process creation for service discovery commands"},
            {"type": "Audit Logs", "location": "Linux audit logs or Windows PowerShell logs", "identify": "Tracking of service-related command execution"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor process creation events for `sc query`, `systemctl`, `tasklist /svc`, or `net start`",
            "Track WMI queries or PowerShell usage related to service enumeration",
            "Detect abnormal discovery behavior outside of IT management windows"
        ],
        "apt": [
            "APT1", "Turla", "OilRig", "Emissary Panda", "Earth Lusca", "Ke3chang", "Wocao", "InvisiMole", "Poseidon Group", "GreyEnergy"
        ],
        "spl_query": [
            'index=windows_logs (command_line="*sc query*" OR command_line="*tasklist /svc*" OR command_line="*net start*")',
            'index=linux_logs command_line="*systemctl --type=service*" OR command_line="*service --status-all*"'
        ],
        "hunt_steps": [
            "Identify accounts and hosts running service discovery tools",
            "Correlate service discovery with follow-on lateral movement or privilege escalation",
            "Determine if enumeration was done from a newly established persistence mechanism"
        ],
        "expected_outcomes": [
            "Detection of unauthorized or suspicious attempts to enumerate services",
            "Early identification of adversary discovery phase activity"
        ],
        "false_positive": "System administrators and monitoring tools may perform routine service discovery. Validate against known IT operations.",
        "clearing_steps": [
            "Disable unnecessary services exposed via enumeration",
            "Review access control on service management tools",
            "Reimage or isolate hosts used for enumeration if compromise is confirmed"
        ],
        "mitre_mapping": [
            {"tactic": "Lateral Movement", "technique": "T1021.002", "example": "Adversary identifies and targets remote services discovered via `sc query`"}
        ],
        "watchlist": [
            "Commands matching service enumeration patterns",
            "Unauthorized users executing service control utilities",
            "Suspicious execution of `sc`, `systemctl`, or `net start` in bulk"
        ],
        "enhancements": [
            "Deploy Sysmon with command-line auditing for process creation",
            "Use EDR to baseline legitimate service discovery activity",
            "Set up alerting on service queries from non-admin or newly created accounts"
        ],
        "summary": "Adversaries may enumerate system services to gather information that informs later stages of the attack such as lateral movement or persistence.",
        "remediation": "Audit service permissions, monitor service enumeration commands, and limit access to administrative tools.",
        "improvements": "Implement service whitelisting and behavioral detection for enumeration patterns.",
        "mitre_version": "16.1"
    }
