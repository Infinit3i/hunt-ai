def get_content():
    return {
        "id": "T1546",
        "url_id": "T1546",
        "title": "Event Triggered Execution",
        "description": "Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events such as logons or application launches.",
        "tags": ["event-driven", "persistence", "privilege escalation"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "",
        "os": "IaaS, Linux, Office Suite, SaaS, Windows, macOS",
        "tips": [
            "Monitor registry and WMI changes associated with event-based triggers",
            "Use Sysinternals Autoruns to identify abnormal persistence entries",
            "Correlate process creation events with known trigger points like logon or file access"
        ],
        "data_sources": "Cloud Service: Cloud Service Modification, Command: Command Execution, File: File Creation, File: File Metadata, File: File Modification, Module: Module Load, Process: Process Creation, WMI: WMI Creation, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "Windows Registry", "source": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "destination": "Persistence Trigger"},
            {"type": "WMI", "source": "Event Consumers", "destination": "Event Filters"},
            {"type": "Command", "source": "PowerShell/CLI", "destination": "Scheduled Tasks"},
            {"type": "Process", "source": "", "destination": "Abnormal child processes"},
            {"type": "File", "source": "", "destination": "Dropped scripts or binaries"},
            {"type": "Cloud Service", "source": "", "destination": "Automation rule triggers"},
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