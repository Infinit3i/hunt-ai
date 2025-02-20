def get_content():
    return {
        "id": "T1083",
        "url_id": "T1083",
        "title": "File and Directory Discovery",
        "tactic": "Discovery",
        "data_sources": "File Monitoring, Process Monitoring, Windows Registry, API Monitoring",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries attempting to discover files and directories to identify valuable data for exfiltration or further attacks.",
        "scope": "Monitor file access attempts, recursive directory listings, and suspicious process interactions with the file system.",
        "threat_model": "Adversaries may attempt to enumerate files and directories to gather intelligence before staging or exfiltrating sensitive data.",
        "hypothesis": [
            "Are there processes performing large-scale file enumeration?",
            "Are there users accessing multiple directories they do not typically access?",
            "Are file discovery commands being executed from unusual locations or at odd hours?"
        ],
        "log_sources": [
            {"type": "File Access Logs", "source": "Sysmon (Event ID 11 - File Creation), Windows Security Logs (Event ID 4663), AuditD (Linux)"},
            {"type": "Process Execution Logs", "source": "Sysmon (Event ID 1 - Process Creation), Windows Event Logs"},
            {"type": "Registry Monitoring", "source": "Windows Registry, Sysmon Event ID 13"},
            {"type": "Command Execution Logs", "source": "Powershell Logging (Event ID 4104), Bash History"}
        ],
        "detection_methods": [
            "Monitor file system activity for mass enumeration of files and directories.",
            "Detect execution of commands commonly used for directory discovery (e.g., `dir`, `ls`, `find`).",
            "Identify anomalous access to sensitive directories or configuration files.",
            "Correlate user activity with historical patterns to identify deviations."
        ],
        "spl_query": "index=filesystem EventCode=11 OR EventCode=4663 | stats count by ProcessName, FilePath, User | where count > 50",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1083",
        "hunt_steps": [
            "Run queries in SIEM to detect mass file enumeration activities.",
            "Analyze process execution logs to identify suspicious directory access attempts.",
            "Correlate with user activity logs to determine if access was authorized.",
            "Investigate processes interacting with sensitive directories without prior history.",
            "Validate findings and escalate to Incident Response if needed."
        ],
        "expected_outcomes": [
            "File enumeration activity detected: Investigate process and user account for further suspicious activity.",
            "No malicious activity found: Improve baseline detection rules and refine false positive filtering."
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1083 (File and Directory Discovery)", "example": "Adversary scans for sensitive files and directories on a compromised system"}
        ],
        "watchlist": [
            "Monitor excessive file access from non-admin accounts.",
            "Track execution of `dir`, `ls`, `find`, or similar file discovery commands.",
            "Flag unusual access attempts to confidential document directories."
        ],
        "enhancements": [
            "Enable detailed logging of file access events.",
            "Restrict access to sensitive directories and enforce least privilege principles.",
            "Use behavioral analytics to detect abnormal file enumeration patterns."
        ],
        "summary": "Monitor and mitigate unauthorized attempts to enumerate files and directories.",
        "remediation": "Investigate unauthorized file access attempts, enforce access controls, and implement anomaly detection.",
        "improvements": "Enhance detection capabilities with machine learning models and behavior-based analytics."
    }
