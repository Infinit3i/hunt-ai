def get_content():
    return {
        "id": "T1211",
        "url_id": "T1211",
        "title": "Exploitation for Defense Evasion",
        "description": "Adversaries may exploit a system or application vulnerability to bypass security features.",
        "tags": ["Defense Evasion", "Exploit", "Security Software Bypass", "Cloud Exploitation", "Evasion"],
        "tactic": "Defense Evasion",
        "protocol": "Local Execution, API Abuse, Cloud Provider APIs",
        "os": "Windows, Linux, macOS, IaaS, SaaS",
        "tips": [
            "Regularly update and patch security software and infrastructure platforms.",
            "Monitor for abnormal behavior from defensive tools and logs disappearing unexpectedly.",
            "Analyze application crash patterns that may indicate failed or successful exploit attempts."
        ],
        "data_sources": "Application Log, Process Monitoring",
        "log_sources": [
            {"type": "Application Log", "source": "Security Software, Syslog", "destination": ""},
            {"type": "Process", "source": "Process Creation Events", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Exploit Payload", "location": "Local System or Cloud API", "identify": "Scripts or binaries targeting antivirus or EDR bypass"},
            {"type": "Recon Output", "location": "Command-line tools", "identify": "Security software enumeration and checks"}
        ],
        "destination_artifacts": [
            {"type": "Security Software Logs", "location": "ProgramData or /var/log", "identify": "Unexpected log deletion or crash logs"},
            {"type": "API Logs", "location": "CloudTrail, Azure Monitor, GCP Logging", "identify": "Abuse or bypass of logging APIs or misconfigured SaaS endpoints"}
        ],
        "detection_methods": [
            "Detect abnormal termination of antivirus or EDR processes.",
            "Look for process creation anomalies immediately following privilege escalation or lateral movement.",
            "Correlate failed login or script activity with disappearance of logs or silent failures in detection tools."
        ],
        "apt": ["APT28", "GhostToken-related groups", "Unattributed cloud-based phishing operators"],
        "spl_query": [
            "index=edr_logs OR index=process_logs (process_name=\"*av*\" OR process_name=\"*defender*\" OR command_line=\"*disable*\" OR command_line=\"*bypass*\") \n| stats count by host, user, process_name, command_line",
            "index=cloud_logs event_type=api_call api_action=*logging* outcome=fail OR api_action=*delete* \n| stats count by user, service, api_action"
        ],
        "hunt_steps": [
            "Search for commands that attempt to stop or modify antivirus/EDR functionality.",
            "Review cloud API logs for privilege escalation and silent disabling of monitoring tools.",
            "Correlate timing of log gaps with new tool drops or lateral movement activity."
        ],
        "expected_outcomes": [
            "Exploitation attempts detected targeting security controls.",
            "No evasion identified, confirming control resilience.",
            "Log disappearance or tool crashes confirmed as indicators of compromise."
        ],
        "false_positive": "Legitimate system administrators may disable or restart security tools for updates or compatibility. Validate intent and source.",
        "clearing_steps": [
            "Restore affected security services to operational status.",
            "Patch the exploited vulnerability if identified.",
            "Reinstate logging configurations and verify retention settings.",
            "Conduct memory analysis for in-memory-only payloads."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-unauthorized-privilege-escalation"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1211", "example": "Exploiting antivirus kernel vulnerabilities to bypass detection"},
            {"tactic": "Defense Evasion", "technique": "T1562.001", "example": "Disabling security tools via exploit-induced crashes"},
            {"tactic": "Initial Access", "technique": "T1566.002", "example": "Using SaaS vulnerability (e.g., GhostToken) to evade detection and deploy payloads"}
        ],
        "watchlist": [
            "New crashes or stops of security software processes.",
            "Unusual behavior from admin tools targeting anti-malware services.",
            "Cloud API calls suppressing or redirecting logs"
        ],
        "enhancements": [
            "Enable tamper protection on all security controls.",
            "Utilize cloud-native anomaly detection in SaaS and IaaS logging environments.",
            "Segment roles and apply least privilege in cloud environments to prevent log evasion."
        ],
        "summary": "Adversaries exploit vulnerabilities in security tools or infrastructure to bypass defenses and hide their presence, often targeting AV, EDR, or cloud-based controls.",
        "remediation": "Apply available patches, validate logging systems, and restore control visibility across endpoints and cloud environments.",
        "improvements": "Automate detection of defensive tool tampering, establish crash alerting for EDR/AV, and harden access controls for logging APIs.",
        "mitre_version": "16.1"
    }
