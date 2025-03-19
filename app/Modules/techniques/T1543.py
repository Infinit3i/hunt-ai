def get_content():
    return {
        "id": "T1543",
        "url_id": "T1543",
        "title": "Create or Modify System Process",
        "tactic": "Persistence",
        "description": "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. Attackers may install new services, daemons, or agents that execute at startup or at regular intervals to establish persistence. They may also modify existing services to achieve similar effects.",
        "tags": ["Persistence", "Privilege Escalation", "System Processes"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "OS API, Windows Services, System Daemons",
        "os": ["Windows", "Linux", "macOS", "Containers"],
        "tips": [
            "Monitor for changes to system processes that do not correlate with known software or patch cycles.",
            "Establish a baseline of legitimate system services and compare changes against it.",
            "Analyze process call trees for anomalies and unexpected child processes."
        ],
        "data_sources": "Process Creation, Service Creation, Registry Modification, File Creation, Driver Load, OS API Execution",
        "log_sources": [
            {"type": "Process Execution Logs", "source": "Sysmon (Event ID 1), Windows Security Logs"},
            {"type": "Registry Modification Logs", "source": "Sysmon (Event ID 13), Windows Event Logs"},
            {"type": "Service Creation Logs", "source": "Windows Event Logs (Event ID 7045)"},
        ],
        "detection_methods": [
            "Monitor service creation logs for unauthorized modifications.",
            "Detect registry changes related to service configurations.",
            "Correlate process execution with known persistence techniques."
        ],
        "apt": ["Yellow Liderc", "Turla", "Sandworm"],
        "spl_query": [
        "`windows` (EventCode=7045 OR EventCode=4697) \n| table _time, Service_Name, Image_Path, User",
        "`windows` EventCode=7045 \n| stats count by ServiceName, ImagePath, User",
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Detect new or modified system services.",
            "Correlate with Threat Intelligence: Investigate suspicious service modifications.",
            "Analyze Process Execution: Identify unusual service behavior.",
            "Investigate Registry and File System Changes: Detect unauthorized modifications.",
            "Validate & Escalate: Confirm malicious activity and escalate if necessary."
        ],
        "expected_outcomes": [
            "Persistence Mechanism Detected: Disable the unauthorized service and investigate further.",
            "No Malicious Activity Found: Improve monitoring rules for system service modifications."
        ],
        "false_positive": "New services installed as part of legitimate software updates.",
        "clearing_steps": [
            "Disable and remove unauthorized system services.",
            "Restore modified configuration files from backups.",
            "Investigate privilege escalation attempts via system process modifications."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1543 (Create or Modify System Process)", "example": "Adversaries create malicious services for persistence."},
            {"tactic": "Privilege Escalation", "technique": "T1543.003 (Windows Service)", "example": "Attackers modify services to execute privileged commands."}
        ],
        "watchlist": [
            "Monitor new and modified system services.",
            "Flag unauthorized registry edits related to service configurations.",
            "Detect suspicious service executions tied to malware signatures."
        ],
        "enhancements": [
            "Restrict administrative privileges to prevent unauthorized service modifications.",
            "Enable logging and monitoring of service creation and modifications.",
            "Deploy endpoint detection to flag persistence techniques."
        ],
        "summary": "Detect adversaries abusing system processes for persistence.",
        "remediation": "Disable malicious services, revoke unauthorized access, and improve detection rules.",
        "improvements": "Enhance security monitoring for service-related persistence mechanisms."
    }
