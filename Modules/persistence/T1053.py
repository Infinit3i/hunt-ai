def get_content():
    return {
        "id": "T1053",
        "url_id": "T1053",
        "title": "Scheduled Task/Job",
        "tactic": "Execution, Persistence, Privilege Escalation",
        "data_sources": "Windows Event Logs, Process Monitoring, Command Execution, File Monitoring",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries creating or modifying scheduled tasks to execute malicious code.",
        "scope": "Monitor scheduled task creation and modifications across operating systems to detect persistence mechanisms.",
        "threat_model": "Attackers leverage scheduled tasks to execute malicious scripts or programs at specified times or system events, gaining persistence and privilege escalation.",
        "hypothesis": [
            "Are new scheduled tasks being created by unauthorized users?",
            "Are scheduled tasks executing suspicious commands or scripts?",
            "Is there an increase in scheduled task modifications outside of normal administrative activity?"
        ],
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Event ID 4698 (Task Created), Event ID 4702 (Task Updated), Event ID 4699 (Task Deleted)"},
            {"type": "Process Monitoring", "source": "Sysmon Event ID 1 (Process Creation)"},
            {"type": "Command Execution", "source": "Audit command-line activity related to schtasks.exe, crontab, at, systemd timers"},
            {"type": "File Monitoring", "source": "Monitor changes to scheduled task XML files and cron job files"}
        ],
        "detection_methods": [
            "Monitor for scheduled task creation or modification events.",
            "Analyze command-line execution for suspicious scheduled task commands.",
            "Identify persistence mechanisms through automated or hidden scheduled tasks.",
            "Detect execution of scripts or executables from unusual locations via scheduled tasks."
        ],
        "spl_query": "index=windows EventCode=4698 OR EventCode=4702 OR EventCode=4699 | stats count by TaskName, User, Command",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1053",
        "hunt_steps": [
            "Run Queries in SIEM to detect newly created or modified scheduled tasks.",
            "Investigate task names, execution commands, and associated user accounts.",
            "Check if scheduled tasks execute scripts or binaries from unauthorized locations.",
            "Validate scheduled tasks against normal administrative activity.",
            "Escalate suspicious findings to incident response for further analysis."
        ],
        "expected_outcomes": [
            "Detection of unauthorized scheduled task creation or modification.",
            "Identification of adversaries using scheduled tasks for persistence.",
            "Prevention of unauthorized code execution via scheduled tasks."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1053 (Scheduled Task/Job)", "example": "Adversaries create scheduled tasks to execute malware on reboot."},
            {"tactic": "Persistence", "technique": "T1053 (Scheduled Task/Job)", "example": "Attackers modify existing tasks to maintain persistence."},
            {"tactic": "Privilege Escalation", "technique": "T1053 (Scheduled Task/Job)", "example": "Adversaries abuse scheduled tasks to execute as SYSTEM."}
        ],
        "watchlist": [
            "Monitor scheduled task creation by unauthorized users.",
            "Detect scheduled tasks executing from suspicious directories.",
            "Analyze task execution frequency for hidden persistence mechanisms."
        ],
        "enhancements": [
            "Restrict task creation to authorized administrators only.",
            "Implement logging for all scheduled task executions.",
            "Regularly audit scheduled task configurations for anomalies."
        ],
        "summary": "Monitor scheduled task creation and modification to detect adversarial persistence.",
        "remediation": "Investigate unauthorized scheduled tasks, disable malicious tasks, and improve access controls.",
        "improvements": "Enhance monitoring of task creation events and implement stricter execution policies."
    }
