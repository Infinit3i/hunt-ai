def get_content():
    return {
        "id": "T1053.002",
        "url_id": "T1053/002",
        "title": "Scheduled Task/Job: At",
        "description": "Adversaries may abuse the 'at' utility for task scheduling to execute malicious code. It is deprecated in favor of 'schtasks' but can still be used on Windows, Linux, and macOS for initial or recurring execution. It requires local administrative rights and the Task Scheduler service to be running.",
        "tags": ["Persistence", "Execution", "Privilege Escalation", "Lateral Movement"],
        "tactic": "Execution, Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": ["Monitor scheduled tasks for unknown entries.", "Look for suspicious task creation or modification."],
        "data_sources": "Command: Command Execution, File: File Modification, Network Traffic: Network Traffic Flow, Process: Process Creation, Scheduled Job: Scheduled Job Creation",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "File", "source": "File Modification", "destination": ""},
            {"type": "Network", "source": "Network Traffic Flow", "destination": ""},
            {"type": "Process", "source": "Process Creation", "destination": ""},
            {"type": "Scheduled Job", "source": "Scheduled Job Creation", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Scheduled Job", "location": "Task Creation", "identify": "Task created or modified by 'at' utility"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "File Modification", "identify": "Files modified or created by scheduled task execution"}
        ],
        "detection_methods": ["Monitor Task Scheduler stores for changes.", "Use event logging for task creation and changes."],
        "apt": [],
        "spl_query": [],
        "hunt_steps": ["Search for tasks using the 'at' utility.", "Monitor for task modifications outside expected changes."],
        "expected_outcomes": ["Identification of unauthorized tasks or code execution.", "Detection of persistence mechanisms via scheduled tasks."],
        "false_positive": "Legitimate scheduled tasks created for system administration or software installation.",
        "clearing_steps": ["Remove unauthorized tasks created via 'at'.", "Disable the 'at' service or limit its use."],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1053", "example": "Task scheduled with 'at' utility."}
        ],
        "watchlist": ["Monitor for unusual task creation or modification.", "Watch for outlier processes scheduled for execution."],
        "enhancements": ["Enable scheduled task event logging for detailed tracking.", "Monitor for privileged access to 'at' utility."],
        "summary": "'At' utility abuse can lead to persistent access by scheduling malicious tasks.",
        "remediation": "Limit use of the 'at' utility and restrict access to administrative users.",
        "improvements": "Implement strict access control and auditing for task scheduling utilities.",
        "mitre_version": "1.1"
    }
