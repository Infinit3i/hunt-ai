def get_content():
    return {
        "id": "T1518",
        "url_id": "T1518",
        "title": "Software Discovery",
        "tactic": "Discovery",
        "data_sources": "Process Monitoring, File Monitoring, Windows Event Logs, Endpoint Detection & Response (EDR)",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries attempting to enumerate installed software and system configurations to identify security weaknesses.",
        "scope": "Monitor for suspicious commands or processes querying installed software lists or system details.",
        "threat_model": "Adversaries may attempt to discover installed software and system configurations to identify security gaps or determine potential targets for exploitation.",
        "hypothesis": [
            "Are unauthorized users or processes querying installed software lists?",
            "Are scripts or malware performing software inventory checks?",
            "Are there unusual access patterns to system registry keys or package management tools?"
        ],
        "log_sources": [
            {"type": "Process Execution Logs", "source": "Sysmon (Event ID 1 - Process Creation), Windows Event Logs"},
            {"type": "Registry Monitoring", "source": "Sysmon (Event ID 13 - Registry Modification), Windows Registry Logs"},
            {"type": "File System Monitoring", "source": "Sysmon (Event ID 11 - File Creation), Linux AuditD"},
            {"type": "EDR Logs", "source": "CrowdStrike, Defender ATP, Carbon Black"}
        ],
        "detection_methods": [
            "Monitor execution of commands commonly used for software discovery (e.g., `wmic product get`, `Get-WmiObject Win32_Product`, `dpkg -l`).",
            "Detect registry queries accessing installed software keys (e.g., `HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall`).",
            "Identify processes querying system package management tools (e.g., `rpm -qa`, `brew list`).",
            "Correlate software discovery commands with known attack techniques and threat intelligence sources."
        ],
        "spl_query": "index=system sourcetype=process_logs (command=\"wmic product get\" OR command=\"Get-WmiObject Win32_Product\") | stats count by user, process_name, command",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1518",
        "hunt_steps": [
            "Run queries in SIEM to detect mass software enumeration activities.",
            "Analyze process execution logs to identify suspicious use of system inventory commands.",
            "Correlate software discovery patterns with user activity logs to detect unauthorized access attempts.",
            "Investigate processes accessing multiple registry keys related to installed software.",
            "Validate findings and escalate to Incident Response if needed."
        ],
        "expected_outcomes": [
            "Software discovery activity detected: Investigate source process and user account for further suspicious activity.",
            "No malicious activity found: Improve baseline detection rules and refine false positive filtering."
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1518 (Software Discovery)", "example": "Adversary queries installed software to identify security gaps and potential exploitation targets."}
        ],
        "watchlist": [
            "Monitor execution of `wmic`, `Get-WmiObject`, `dpkg -l`, `rpm -qa`, or similar commands.",
            "Track registry queries accessing software installation keys.",
            "Flag software discovery activities outside normal administrative workflows."
        ],
        "enhancements": [
            "Enable detailed logging of process executions related to software enumeration.",
            "Restrict execution of system inventory commands to privileged users.",
            "Use behavioral analytics to detect anomalous software discovery attempts."
        ],
        "summary": "Monitor and mitigate unauthorized attempts to enumerate installed software within an environment.",
        "remediation": "Investigate unauthorized software discovery attempts, enforce access controls, and implement anomaly detection.",
        "improvements": "Enhance detection capabilities with machine learning models and behavior-based analytics."
    }
