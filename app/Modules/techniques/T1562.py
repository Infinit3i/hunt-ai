def get_content():
    return {
        "id": "T1562",
        "url_id": "T1562",
        "title": "Impair Defenses",
        "description": "Adversaries may modify or disable security mechanisms to avoid detection or delay response. This includes targeting endpoint defenses such as antivirus, EDR, firewalls, event logs, update services, or disabling monitoring altogether. These actions enable adversaries to operate stealthily and may also help propagate further attacks across the environment.",
        "tags": ["defense evasion", "persistence", "logging", "EDR bypass", "firewall", "antivirus", "forensics evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows, Linux, macOS, Network, Containers, IaaS, Identity Provider, Office Suite",
        "tips": [
            "Harden security tools with tamper protection and service monitoring.",
            "Audit scheduled tasks, group policies, and services for suspicious changes.",
            "Enable integrity monitoring and redundant telemetry collection where possible."
        ],
        "data_sources": "Process, Windows Registry, File, Service, Firewall, Cloud Service, User Account",
        "log_sources": [
            {"type": "Process", "source": "Endpoint Security Agent", "destination": ""},
            {"type": "Windows Registry", "source": "Registry", "destination": ""},
            {"type": "Firewall", "source": "Firewall Logs", "destination": ""},
            {"type": "Service", "source": "System Services", "destination": ""},
            {"type": "User Account", "source": "Active Directory", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Script", "location": "Startup folders, login scripts", "identify": "Persistence via tampering with defensive configuration"},
            {"type": "Command Line", "location": "Parent-child process tree", "identify": "Use of tools to kill or disable security software"},
            {"type": "Windows Registry", "location": "HKLM\\Software\\Policies", "identify": "Modified keys disabling antivirus or logging"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "C:\\Program Files\\SecurityTool", "identify": "Disabled or terminated EDR/AV services"},
            {"type": "File", "location": "%WINDIR%\\System32\\drivers", "identify": "Deleted drivers related to security monitoring"},
            {"type": "Service", "location": "/etc/systemd/system", "identify": "Suppressed or altered Linux/macOS daemon services"}
        ],
        "detection_methods": [
            "Monitor process and service modification (e.g., via Event ID 7045 or 4688)",
            "Track antivirus/EDR agent communication health",
            "Detect registry and configuration tampering",
            "Alert on mass log deletion or log source silencing"
        ],
        "apt": ["APT35", "Stuxnet", "UNC3886"],
        "spl_query": [
            "index=security_logs EventCode=7036 Message=\"*stopped*\" \n| search ServiceName=*Defender* OR *Security* \n| stats count by ServiceName, host, _time",
            "index=registry_logs KeyPath=\"*Policies*\" ValueName IN (*Disable*, *Enable*) \n| stats values(RegistryValueData) by host, KeyPath, ValueName"
        ],
        "hunt_steps": [
            "Check for known security services terminated in the past 7 days",
            "Look for unsigned scripts or binaries interacting with security tools",
            "Identify registry changes under common AV/EDR policy keys"
        ],
        "expected_outcomes": [
            "Early warning for attempts to disable logging or monitoring",
            "Confirmation of services vital to visibility being interfered with",
            "Attribution of EDR evasion or log deletion to specific users or malware"
        ],
        "false_positive": "Some administrative tools or updates may trigger these detections—verify initiators and execution context.",
        "clearing_steps": [
            "Reinstall or repair impaired security software",
            "Restore registry keys or configuration files to enforce policies",
            "Re-enable and monitor critical logging and service statuses"
        ],
        "clearing_playbook": [],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1562", "example": "Disabling Windows Defender via registry or PowerShell"},
            {"tactic": "Persistence", "technique": "T1547.001", "example": "Malicious service used to disable antivirus upon boot"}
        ],
        "watchlist": [
            "Tools known to disable AV or EDR (e.g., Defender Control, Process Hacker)",
            "Repeated service stop events tied to security tools",
            "Lack of logs from previously active endpoints"
        ],
        "enhancements": [
            "Deploy security solutions with tamper protection features",
            "Enable immutable logging where feasible (e.g., cloud audit logs)",
            "Integrate alerting for gaps in expected telemetry sources"
        ],
        "summary": "T1562 covers a wide range of techniques used to degrade or completely disable security tooling. This is a common tactic used by threat actors to reduce the risk of detection and response once inside a network. It may be implemented at various levels—from local configurations to cloud-wide visibility mechanisms.",
        "remediation": "Audit and enforce service protections. Use group policies and endpoint protection tools with self-defense and recovery mechanisms.",
        "improvements": "Automate detection of impaired log sources or terminated AV agents. Investigate and document authorized exceptions.",
        "mitre_version": "16.1"
    }
