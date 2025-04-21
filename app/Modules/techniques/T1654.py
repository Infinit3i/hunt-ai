def get_content():
    return {
        "id": "T1654",
        "url_id": "T1654",
        "title": "Log Enumeration",
        "description": "Adversaries may enumerate local, remote, or cloud-based system and security logs to identify valuable insights, such as user authentication activity, vulnerable software, or incident response indicators. Techniques may include native tools like `wevtutil.exe`, PowerShell, Azure VM Agent binaries, or access to SIEM platforms. Enumeration helps adversaries tailor subsequent actions for persistence, lateral movement, and evasion.",
        "tags": ["log-access", "discovery", "enumeration", "cloud", "SIEM", "Windows-event-logs"],
        "tactic": "Discovery",
        "protocol": "",
        "os": "IaaS, Linux, Windows, macOS",
        "tips": [
            "Restrict access to system and security logs to only authorized users or services",
            "Audit and alert on log access from unusual processes or users",
            "Encrypt sensitive logs and rotate access tokens frequently"
        ],
        "data_sources": "Command: Command Execution, File: File Access, Process: Process Creation",
        "log_sources": [
            {"type": "Command", "source": "PowerShell, wevtutil, bash", "destination": ""},
            {"type": "File", "source": "Security/Event Logs, Syslog, /var/log/", "destination": ""},
            {"type": "Process", "source": "SIEM audit logs, Defender logs", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Command Execution", "location": "Local or remote endpoints", "identify": "Tools like wevtutil.exe, Get-WinEvent, or CollectGuestLogs.exe"},
            {"type": "API Access", "location": "Cloud agent activity", "identify": "Azure GuestAgent activity, CloudTrail log pull"},
            {"type": "SIEM Access", "location": "Logging infrastructure", "identify": "Queries from unauthorized users"}
        ],
        "destination_artifacts": [
            {"type": "Extracted Logs", "location": "Exfil destination or adversary tooling", "identify": "Compressed log archives or export scripts"},
            {"type": "Log Filters", "location": "Command arguments", "identify": "Specific filters for security logs or authentication entries"},
            {"type": "Log Watching", "location": "Cloud console or agents", "identify": "Real-time log access indicating active tracking of IR"}
        ],
        "detection_methods": [
            "Monitor access to security event logs by unauthorized users",
            "Track invocation of logging utilities with export or filter flags",
            "Alert on abnormal cloud agent activities pulling security logs",
            "Detect read or exfil activity against large log files"
        ],
        "apt": [
            "APT41", "Volt Typhoon", "Cadet Blizzard", "Lazarus Group"
        ],
        "spl_query": "index=security OR index=syslog OR index=cloudtrail\n| search process_name IN (wevtutil.exe, Get-WinEvent, CollectGuestLogs.exe)\n| stats count by user, host, command_line",
        "spl_rule": "https://research.splunk.com/detections/tactics/discovery/",
        "elastic_rule": "https://grep.app/search?f.repo=elastic%2Fdetection-rules&q=T1654",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1654",
        "hunt_steps": [
            "Check for use of native log export tools (PowerShell, wevtutil) from non-administrative accounts",
            "Analyze large log file read activity or compression patterns",
            "Correlate Azure/AWS/GCP API calls with download or export behavior",
            "Review abnormal queries or access patterns from SIEMs or security appliances"
        ],
        "expected_outcomes": [
            "Identified log access by adversary tools or compromised accounts",
            "Prevented exfiltration of security event data",
            "Hardened monitoring on log file enumeration and agent behavior"
        ],
        "false_positive": "SIEM operations teams or forensic responders may routinely access logs in similar ways. Validate context and tool lineage.",
        "clearing_steps": [
            "Audit access logs and revoke suspicious access tokens",
            "Alert and isolate the user or process accessing restricted logs",
            "Regenerate audit policies or event forwarder configs if tampered"
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1654 (Log Enumeration)", "example": "Use of PowerShell to query Security event logs for login activity"},
            {"tactic": "Discovery", "technique": "T1518 (Software Discovery)", "example": "Review of logs to determine antivirus and EDR software"},
            {"tactic": "Discovery", "technique": "T1018 (Remote System Discovery)", "example": "Analyzing logs to locate connected hosts or devices"}
        ],
        "watchlist": [
            "Watch for 'CollectGuestLogs.exe' usage in cloud environments",
            "Monitor log export behavior, especially involving Event IDs 4624, 4688, 1102",
            "Alert on use of compression or archiving tools targeting log directories"
        ],
        "enhancements": [
            "Implement log access monitoring in SIEM with user and process correlation",
            "Enable cloud agent alerts on suspicious log collection",
            "Add honeypot event logs to detect adversary probing"
        ],
        "summary": "Log Enumeration allows adversaries to explore logs for reconnaissance, incident response awareness, and evasion planning. Detection requires a focus on access, tool usage, and downstream data handling.",
        "remediation": "Limit access to sensitive logs, investigate abnormal log queries, and monitor for log export or compression activity.",
        "improvements": "Enhance audit policies, track log tool usage by process lineage, and automate alerts on common adversary log access techniques.",
        "mitre_version": "16.1"
    }
