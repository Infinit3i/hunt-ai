def get_content():
    return {
        "id": "T1562.006",
        "url_id": "T1562/006",
        "title": "Impair Defenses: Indicator Blocking",
        "description": "Adversaries may attempt to block indicators or events typically captured by sensors to avoid detection. This may involve redirecting logs, disabling host-based sensors such as Event Tracing for Windows (ETW), or tampering with telemetry settings via the registry or admin utilities like PowerShell and WMI. For example, adversaries may change the `File` path in `HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security` to redirect logs to a different .evtx file, hiding their activities without requiring a reboot.",
        "tags": ["sensor evasion", "event blocking", "ETW", "registry", "log manipulation", "SIEM evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor registry keys controlling log destinations and sensor configurations.",
            "Detect sudden or selective absence of telemetry from previously active sensors.",
            "Correlate log gaps with command execution activity and privilege escalation."
        ],
        "data_sources": "Command, Process, Sensor Health, Windows Registry",
        "log_sources": [
            {"type": "Command", "source": "CLI", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Sensor Health", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Registry Key Modification", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security", "identify": "Redirected Security logs to new file"},
            {"type": "PowerShell Usage", "location": "Set-EtwTraceProvider", "identify": "Used to disable or filter ETW events"},
            {"type": "Service Control", "location": "WMI or CLI service stops", "identify": "Sensor or telemetry processes stopped"}
        ],
        "destination_artifacts": [
            {"type": "ETW Registry", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger", "identify": "Provider GUIDs or trace configs altered"},
            {"type": "Syslog Config", "location": "/etc/rsyslog.conf or /etc/syslog-ng", "identify": "Disabled or redirected logs on Linux"},
            {"type": "SIEM Rules", "location": "SIEM alerting gaps", "identify": "Telemetry suddenly absent from endpoint"}
        ],
        "detection_methods": [
            "Correlate sudden disappearance of sensor logs with active sessions or changes to ETW registry keys",
            "Detect use of PowerShell's Set-EtwTraceProvider cmdlet",
            "Monitor Event ID 16 from Sysmon and provider removal via WMI subscriptions",
            "Log creation or changes in registry locations controlling ETW or syslog configuration"
        ],
        "apt": ["APT41", "LemonDuck", "HermeticWiper", "WoodyRAT"],
        "spl_query": [
            "index=wineventlog EventCode=16 source_name=Microsoft-Windows-Sysmon \\n| stats count by host, user, Image, EventData",
            "index=wineventlog source_name=Microsoft-Windows-WMI-Activity \\n| search EventData IN (*RemoveTraceProvider*, *UnregisterTrace*) \
| stats count by host, EventData"
        ],
        "hunt_steps": [
            "Review registry values under Autologger keys for suspicious provider configs",
            "Check log paths for unexpected redirections or lack of recent entries",
            "Correlate telemetry loss with execution of PowerShell or WMI commands",
            "Hunt for sudden termination of telemetry forwarders or unusual firewall blocks to SIEM" 
        ],
        "expected_outcomes": [
            "Detection of blocked or diverted event sources",
            "Discovery of unauthorized changes in logging behavior or sensor function",
            "Identification of adversarial efforts to evade centralized visibility"
        ],
        "false_positive": "System tools or EDR software may adjust ETW or logging config. Review with context and user validation.",
        "clearing_steps": [
            "Restore registry keys for log paths and ETW configurations to known-good",
            "Restart impacted logging services and re-register trace providers",
            "Re-enable telemetry forwarding or SIEM ingestion rules"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1562.006", "example": "Modifying registry to redirect Security event log to alternate file"},
            {"tactic": "Defense Evasion", "technique": "T1059.001", "example": "Using Set-EtwTraceProvider to filter events"}
        ],
        "watchlist": [
            "ETW providers being removed or reconfigured without system updates",
            "Registry changes in Autologger paths without expected GPO activity",
            "Telemetry flow interruption following use of administrative scripting tools"
        ],
        "enhancements": [
            "Set alerts on deletion or reconfiguration of known ETW provider GUIDs",
            "Deploy tripwire files or test rules to verify uninterrupted logging",
            "Use secure logging transports and validate receipt at SIEM"
        ],
        "summary": "T1562.006 focuses on the adversary's ability to hide activities by blocking indicators or disabling sensors. This prevents collection of key evidence and reduces visibility for defenders. Examples include disabling ETW, redirecting logs, or preventing SIEM ingestion through firewall rules.",
        "remediation": "Harden sensor configurations, lock registry keys associated with logging paths, and monitor for interruption in expected telemetry from all assets.",
        "improvements": "Introduce continuous validation of logging pipeline and integrity of sensor processes through scheduled health checks and heartbeat-based SIEM logic.",
        "mitre_version": "16.1"
    }