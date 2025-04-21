def get_content():
    return {
        "id": "T1569",
        "url_id": "T1569",
        "title": "System Services",
        "description": "Adversaries may abuse system services or daemons to execute commands or programs. This includes interacting with or creating services either locally or remotely. These services may be used for one-time execution or set to run persistently at system boot, enabling long-term foothold and potentially elevated privileges.\n\nSystem services are often targeted due to their high privilege levels and consistent execution. Adversaries can modify existing services or create new ones to execute malicious payloads, often masquerading under legitimate-looking service names or binaries.\n\nIn Windows environments, changes to service configurations may also be reflected in the Registry. On Linux and macOS, system daemons and launch agents/daemons are commonly abused through systemd, init scripts, or launchd/launchctl, respectively.",
        "tags": ["execution", "persistence", "privilege escalation", "services", "init", "systemd", "launchctl", "daemon", "macos", "linux", "windows"],
        "tactic": "Execution",
        "protocol": "N/A",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Look for unusual service names or executable paths when auditing service configurations.",
            "Monitor for services created outside standard patching or installation windows.",
            "Alert on binaries associated with services being modified unexpectedly."
        ],
        "data_sources": "Command Execution, File Modification, Process Creation, Service Creation, Windows Registry Key Modification",
        "log_sources": [
            {"type": "Command Execution", "source": "Sysmon Event ID 1, auditd, Unified Logs", "destination": ""},
            {"type": "File Modification", "source": "EDR, auditd, File Integrity Monitoring", "destination": ""},
            {"type": "Process Creation", "source": "Sysmon, auditd, EDR", "destination": ""},
            {"type": "Service Creation", "source": "Windows Service Control Manager, launchd, systemd logs", "destination": ""},
            {"type": "Windows Registry Key Modification", "source": "Sysmon Event ID 13, Windows Security Logs", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Service Executable", "location": "System folders or user-writable paths", "identify": "Modified or replaced executable"},
            {"type": "Registry Entry", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Services", "identify": "New or modified service entry"}
        ],
        "destination_artifacts": [
            {"type": "Persistent Service", "location": "System startup configuration", "identify": "Malicious service set to run on boot"},
            {"type": "Temporary Execution", "location": "Service called on-demand", "identify": "One-time execution pattern without persistence"}
        ],
        "detection_methods": [
            "Detect service creation using native tools (e.g., `sc`, `New-Service`, `launchctl`, `systemctl`).",
            "Monitor for changes to service executables or configuration paths.",
            "Look for Registry modifications related to Windows service configuration."
        ],
        "apt": [],
        "spl_query": [
            "index=wineventlog OR index=sysmon \n| search EventCode=7045 OR EventCode=1 OR Image=\"*\\services.exe\" \n| stats count by Image, CommandLine, User"
        ],
        "hunt_steps": [
            "Review service creation logs and identify anomalies in service names, binaries, or paths.",
            "Check for newly created services or daemons outside of expected update windows.",
            "Compare changes in service-related registry entries or plist/systemd files to baselines.",
            "Validate execution origin and context of new services using process tree analysis."
        ],
        "expected_outcomes": [
            "Unauthorized service abuse detected: Confirm and escalate as potential persistence or privilege escalation technique.",
            "No abnormal service behavior: Continue baseline refinement and scheduled audits."
        ],
        "false_positive": "Legitimate software installations or updates may create new services or modify existing ones. Validate changes against approved software and patching cycles.",
        "clearing_steps": [
            "Stop the malicious service using appropriate OS-specific tools (`sc stop`, `systemctl stop`, `launchctl unload`).",
            "Delete the service definition and associated files.",
            "Remove any supporting persistence (e.g., registry entries or .plist files)."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1569 (System Services)", "example": "Adversary creates a new service to run a backdoor."},
            {"tactic": "Persistence", "technique": "T1543 (Create or Modify System Process)", "example": "Malware persists via autorun system service."},
            {"tactic": "Privilege Escalation", "technique": "T1543.003 (Windows Service)", "example": "Service created to run payload as SYSTEM."}
        ],
        "watchlist": [
            "Flag service creation/modification attempts by non-administrative users.",
            "Track new services added to autorun locations or launchd/systemd configs.",
            "Alert on services with executables stored in temporary or user-writeable locations."
        ],
        "enhancements": [
            "Implement allowlists for trusted services and paths.",
            "Use endpoint protection tools to monitor service creation and configuration changes.",
            "Automate comparison of service metadata against known good baselines."
        ],
        "summary": "System services are often targeted by adversaries to execute or persist malicious programs. Monitoring service creation and modification is key to detecting such abuse.",
        "remediation": "Terminate the unauthorized service, remove persistence mechanisms, and audit affected systems.",
        "improvements": "Enhance service monitoring, integrate FIM for service paths, and enforce least privilege on service creation tools.",
        "mitre_version": "16.1"
    }
