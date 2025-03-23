def get_content():
    return {
        "id": "T1053.003",  # Tactic Technique ID (e.g., T1556.001)
        "url_id": "T1053/003",  # URL segment for technique reference (e.g., T1556/001)
        "title": "Scheduled Task/Job: Cron",  # Name of the attack technique
        "description": "Adversaries may abuse the cron utility to perform task scheduling for initial or recurring execution of malicious code.",  # Description of the attack technique
        "tags": ["Persistence", "Privilege Escalation", "Execution"],  # Tags associated with the technique
        "tactic": "Persistence",  # Associated MITRE ATT&CK tactic
        "protocol": "",  # Protocol used in the attack technique (empty here)
        "os": "Linux, macOS",  # Targeted operating systems
        "tips": [
            "Monitor scheduled task creation from common utilities using command-line invocation.",
            "Look for changes to tasks that do not correlate with known software, patch cycles, etc.",
            "Suspicious program execution through scheduled tasks may show up as outlier processes."
        ],  # Additional investigation and mitigation tips
        "data_sources": "Command: Command Execution, File: File Modification, Process: Process Creation, Scheduled Job: Scheduled Job Creation",  # List of relevant data sources
        "log_sources": [  # Logs necessary for detection, type should match data sources
            {"type": "Command", "source": "Cron", "destination": ""}
        ],
        "source_artifacts": [  # Artifacts generated on the source machine
            {"type": "Crontab File", "location": "/etc/crontab", "identify": "Cron entries"}
        ],
        "destination_artifacts": [  # Artifacts generated on the destination machine
            {"type": "Crontab File", "location": "/etc/crontab", "identify": "Cron entries"}
        ],
        "detection_methods": [
            "Monitor for cron entry modifications.",
            "Alert on unusual cron entry patterns or timestamps."
        ],  # Techniques for identifying the attack
        "apt": ["APT5", "Unit42", "Red Canary"],  # APT groups known to use this technique
        "spl_query": [
            "| index=sysmon sourcetype=cron | search *"
        ],  # Splunk queries to detect the technique
        "hunt_steps": [
            "Search for new cron jobs created by unknown users or processes.",
            "Look for cron jobs with suspicious or unknown commands."
        ],  # Steps to proactively hunt for threats
        "expected_outcomes": [
            "Identifying malicious cron job entries.",
            "Unusual cron job behavior."
        ],  # Expected results from detection/hunting
        "false_positive": "Cron jobs created by legitimate system administration processes may trigger false positives.",  # Known false positives and how to handle them
        "clearing_steps": [
            "Remove suspicious cron jobs from the crontab file.",
            "Restore crontab files from backup if necessary."
        ],  # Steps for remediation and clearing traces
        "mitre_mapping": [  # Next Mitre Technique that could be used after this one
            {"tactic": "Execution", "technique": "T1053", "example": "Create scheduled tasks for recurring execution."}
        ],
        "watchlist": [
            "Monitor cron logs for unusual entries."
        ],  # Indicators to monitor for potential threats
        "enhancements": [
            "Enhance detection by correlating with other event logs such as process creation or file modification."
        ],  # Suggested improvements to detection
        "summary": "The cron utility can be abused by adversaries to schedule malicious code for execution at system startup or on a recurring basis.",  # High-level summary of the technique
        "remediation": "Remove malicious cron jobs, verify the integrity of crontab files, and restore from a clean backup if necessary.",  # Recommended actions to mitigate risk
        "improvements": "Implement better logging and monitoring on cron job creation and modifications.",  # Suggested ways to improve detection and response
        "mitre_version": "16.1"  # MITRE ATT&CK version
    }
