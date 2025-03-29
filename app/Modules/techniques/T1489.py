def get_content():
    return {
        "id": "T1489",
        "url_id": "T1489",
        "title": "Service Stop",
        "description": "Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services or processes can inhibit or stop response to an incident or aid in the adversary's overall objectives to cause damage to the environment. Adversaries may disable individual services of high importance to an organization, such as MSExchangeIS, or may stop or disable many services to render systems unusable. They may also stop services to conduct data destruction or encryption on their data stores.",
        "tags": ["service stop", "impact", "availability disruption"],
        "tactic": "Impact",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor critical services for unexpected shutdowns.",
            "Correlate service stop events with process creation and registry/service config modifications.",
            "Alert on ChangeServiceConfigW API usage from non-standard binaries."
        ],
        "data_sources": "Command, File, Process, Service, Windows Registry",
        "log_sources": [
            {"type": "Process", "source": "Sysmon", "destination": ""},
            {"type": "Service", "source": "Windows Event Log", "destination": ""},
            {"type": "Windows Registry", "source": "Windows Security", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Windows Event Logs", "location": "Security, System", "identify": "Service stop and config change events (e.g., EventID 7036, 7040, 7045)"},
            {"type": "Registry Hives", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Services", "identify": "Disabled or altered service configurations"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor process creation and correlate with service stop API calls (e.g., ChangeServiceConfigW)",
            "Audit changes to Windows service registry keys",
            "Track usage of system utilities such as sc.exe, net stop, systemctl"
        ],
        "apt": [
            "Olympic Destroyer", "Blockbuster", "EKANS", "WastedLocker", "WannaCry", "Clop", "BlackCat", "Ryuk", "REvil", "Meteor"
        ],
        "spl_query": [
            "index=win_logs EventCode=7036 Message=\"*stopped*\" \n| stats count by ServiceName, host, user",
            "index=win_logs EventCode=7040 Message=\"*service*changed*disabled*\" \n| stats count by ServiceName, host, user"
        ],
        "hunt_steps": [
            "Identify services stopped within short time spans.",
            "Pivot from stopped services to responsible processes.",
            "Check for corresponding service binary path modifications or file deletions."
        ],
        "expected_outcomes": [
            "Critical business services become inaccessible.",
            "Incident response and recovery operations are impaired.",
            "Malware disables services prior to encryption or destruction."
        ],
        "false_positive": "Administrators may stop services during legitimate patching or maintenance. Validate against known change control records.",
        "clearing_steps": [
            "Re-enable stopped services via service manager or registry.",
            "Restore altered service paths and permissions.",
            "Scan and remove malware responsible for disabling services."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "Impact", "technique": "T1489", "example": "Disabling antivirus and backup services to inhibit recovery."},
            {"tactic": "Defense Evasion", "technique": "T1562", "example": "Stopping endpoint detection services to bypass security tools."}
        ],
        "watchlist": [
            "Services repeatedly stopped without user interaction.",
            "Changes to service startup types from Automatic to Disabled.",
            "Systemctl or sc.exe usage on production systems."
        ],
        "enhancements": [
            "Correlate service stop events with registry modification and file deletion.",
            "Use EDR tools to trace process lineage of service-altering commands."
        ],
        "summary": "Stopping critical services helps adversaries disrupt business continuity, inhibit security tools, or prepare for more destructive actions like ransomware or wipers.",
        "remediation": "Reinstate impacted services, restore configurations, and remove malicious components that altered service states.",
        "improvements": "Deploy service whitelisting and monitoring for tampering. Improve alerting on key service disruptions.",
        "mitre_version": "16.1"
    }
