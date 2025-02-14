def get_content():
    return {
        "id": "T1546",
        "url_id": "T1546",
        "title": "Event Triggered Execution",
        "tactic": "Persistence",
        "data_sources": "Process Monitoring, Windows Event Logs, File Monitoring, Registry, Sysmon, EDR",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries using system events to trigger the execution of malicious payloads.",
        "scope": "Monitor system logs, process execution, and registry modifications for indicators of event-triggered execution.",
        "threat_model": "Adversaries leverage event triggers such as scheduled tasks, WMI subscriptions, and other system event handlers to execute malicious code automatically.",
        "hypothesis": [
            "Are there unusual scheduled tasks being created or modified?",
            "Are event triggers being used to execute unexpected processes?",
            "Are there unauthorized modifications to registry keys associated with event execution?"
        ],
        "log_sources": [
            {"type": "Process Execution Logs", "source": "Sysmon (Event ID 1 - Process Creation), Windows Security Logs"},
            {"type": "Registry Modification Logs", "source": "Sysmon (Event ID 13 - Registry Modification), Windows Event Logs"},
            {"type": "Event Trigger Logs", "source": "Windows Task Scheduler, WMI Logs, SystemD logs (Linux)"},
            {"type": "Threat Intelligence Feeds", "source": "VirusTotal, Hybrid Analysis, MISP"}
        ],
        "detection_methods": [
            "Monitor for scheduled tasks and WMI event subscriptions.",
            "Detect suspicious registry modifications related to event triggers.",
            "Correlate process execution logs with known event-based execution patterns."
        ],
        "spl_query": ["index=windows sourcetype=WinEventLog EventCode=4698 OR EventCode=4702 | stats count by TaskName, CreatorProcessName, User | sort - count",],
        "hunt_steps": [
            "Run queries in SIEM to detect newly created scheduled tasks or WMI event subscriptions.",
            "Correlate detected tasks with known malware execution patterns.",
            "Investigate whether event-based execution is occurring outside expected system behavior.",
            "Check registry modifications and process execution logs for suspicious activities.",
            "Validate findings and escalate for further investigation."
        ],
        "expected_outcomes": [
            "Malicious Event Triggered Execution Detected: Investigate further, disable the trigger, and remove adversary persistence.",
            "No Malicious Activity Found: Improve event execution monitoring and refine detection logic."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1546 (Event Triggered Execution)", "example": "Malicious scheduled task executing payloads"},
            {"tactic": "Execution", "technique": "T1204.002 (User Execution - Malicious File)", "example": "User opens a file that registers a malicious event trigger"},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Attackers delete event logs to hide traces of execution"}
        ],
        "watchlist": [
            "Monitor newly created scheduled tasks and modified system event triggers.",
            "Detect unusual WMI event subscriptions or registry changes related to event execution.",
            "Alert on scheduled task modifications in critical system directories."
        ],
        "enhancements": [
            "Restrict permissions for creating and modifying scheduled tasks.",
            "Implement application allowlisting to prevent unauthorized execution.",
            "Enable logging and monitoring for event-based execution mechanisms."
        ],
        "summary": "Document detected event-triggered execution attempts and analyze associated system modifications.",
        "remediation": "Disable unauthorized event triggers, remove malicious scheduled tasks, and review user activity logs.",
        "improvements": "Enhance detection capabilities for scheduled tasks and WMI subscriptions by refining correlation rules."
    }