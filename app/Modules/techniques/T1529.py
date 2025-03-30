def get_content():
    return {
        "id": "T1529",
        "url_id": "T1529",
        "title": "System Shutdown/Reboot",
        "description": "Adversaries may initiate a shutdown or reboot of a system to disrupt availability, impede incident response, or complete destructive actions. This can occur after other impact techniques such as disk wiping or inhibiting system recovery. System shutdowns may be performed using built-in operating system commands (e.g., `shutdown`, `reboot`, `halt`) or via remote network device command line interfaces (e.g., `reload` for routers or switches). This action prevents users and administrators from accessing systems, and can delay recovery efforts by disabling forensics or response tools running in volatile memory.",
        "tags": ["impact", "destruction", "availability", "shutdown", "reboot", "T1529"],
        "tactic": "Impact",
        "protocol": "",
        "os": "Linux, Network, Windows, macOS",
        "tips": [
            "Monitor for system shutdown events tied to non-administrative users or unauthorized remote access.",
            "Alert on use of shutdown/reboot commands on critical infrastructure systems.",
            "Implement delays or challenge prompts before allowing shutdown in high-availability systems."
        ],
        "data_sources": "Command Execution, Process Creation, Sensor Health",
        "log_sources": [
            {"type": "Process", "source": "Process Creation", "destination": ""},
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "Sensor Health", "source": "Host Status", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Process", "location": "System Audit Logs", "identify": "Unexpected invocation of shutdown, reboot, or halt"},
            {"type": "Event Logs", "location": "Windows Event Viewer", "identify": "Event ID 1074 (shutdown), 6006 (event log stopped)"},
            {"type": "Network CLI", "location": "Router/Switch Logs", "identify": "Reload or reboot commands from untrusted IP"}
        ],
        "destination_artifacts": [
            {"type": "System Availability", "location": "Uptime Monitoring", "identify": "Sudden loss of service followed by reboot"},
            {"type": "SIEM Alert", "location": "Security Console", "identify": "Reboot/shutdown from endpoint with concurrent threat activity"},
            {"type": "EDR Logs", "location": "Endpoint Telemetry", "identify": "Final action before agent loss"}
        ],
        "detection_methods": [
            "Windows Event Log monitoring for Event IDs 1074 and 6006.",
            "Process creation logs detecting use of shutdown/reboot-related binaries.",
            "Sensor health and availability dashboards showing abrupt offline behavior across multiple endpoints."
        ],
        "apt": [
            "APT28",  # Olympic Destroyer / NotPetya used system reboot post-wiper activity
            "APT38",  # Linked to HermeticWiper, which also included shutdown commands
            "Sandworm Team",  # Linked to Industroyer, NotPetya, and broader destructive ops with shutdown components
            "Agrius",  # Associated with impact-focused campaigns including reboots post-wipe
            "Moses Staff",  # Destructive wipers and system reboot activity
            "HermeticWiper Group",  # Seen in Ukraine-targeted attacks triggering shutdowns
            "ROADSWEEP",  # Linked to disk wipers and system reboot/disruption operations
        ],
        "spl_query": [
            'index=wineventlog EventCode=1074 OR EventCode=6006\n| stats count by ComputerName, User, Message',
            'index=os_logs sourcetype=process_creation\n| search process_name="shutdown.exe" OR process_name="reboot" OR process_name="halt"\n| stats count by host, user, command_line',
            'index=network_device_logs\n| search command="reload" OR command="reboot"\n| stats count by device, src_ip'
        ],
        "hunt_steps": [
            "Review system uptime and shutdown logs for critical servers.",
            "Correlate shutdown events with prior disk wipe, recovery inhibition, or malware activity.",
            "Identify users or remote IPs executing shutdown/reboot commands across endpoints or infrastructure."
        ],
        "expected_outcomes": [
            "Early detection of adversary-triggered shutdowns post-impact.",
            "Improved understanding of adversary timeline before system unavailability.",
            "Correlation between destructive techniques and forced shutdowns to complete attack goals."
        ],
        "false_positive": "System administrators or update policies may perform scheduled shutdowns or reboots. Context is required to distinguish malicious activity.",
        "clearing_steps": [
            "Restore power and OS functionality where applicable.",
            "Reset affected systems and review event logs and timelines.",
            "Re-enable logging and incident response agents if disabled due to reboot."
        ],
        "mitre_mapping": [
            {"tactic": "Impact", "technique": "T1529", "example": "Use of shutdown.exe post-disk wipe to hinder recovery"},
            {"tactic": "Impact", "technique": "T1490", "example": "Shutdown after disabling recovery tools or shadow volumes"},
            {"tactic": "Impact", "technique": "T1561.002", "example": "Reboot after corrupting partition tables"}
        ],
        "watchlist": [
            "Unexpected shutdown commands on domain controllers or backup servers",
            "Shutdowns during off-hours or from new administrative accounts",
            "Network device reloads from new CLI IPs or user accounts"
        ],
        "enhancements": [
            "Implement access control policies requiring elevated approval for shutdown on critical systems.",
            "Add SIEM alerts for Event ID 1074 tied to suspicious command-line arguments.",
            "Correlate shutdown events with process trees involving malware, wipers, or ransomware."
        ],
        "summary": "Adversaries may forcibly shutdown or reboot systems to disrupt operations and hinder recovery. This can occur as part of destructive attacks, post-impact cleanup, or to delay incident response.",
        "remediation": "Validate source of shutdowns. Audit user and device logs. Restore service availability and investigate the triggering event.",
        "improvements": "Harden critical systems with delayed shutdown policies. Monitor administrative command-line usage. Improve alerting around system availability drops.",
        "mitre_version": "16.1"
    }
