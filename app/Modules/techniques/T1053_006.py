def get_content():
    return {
        "id": "T1053.006",  # Tactic Technique ID (e.g., T1556.001)
        "url_id": "T1053/006",  # URL segment for technique reference (e.g., T1556/001)
        "title": "Scheduled Task/Job: Systemd Timers",  # Name of the attack technique
        "description": "Adversaries may abuse systemd timers to perform task scheduling for initial or recurring execution of malicious code.",  # Description of the attack technique
        "tags": ["Persistence", "Privilege Escalation", "Execution"],  # Tags associated with the technique
        "tactic": "Persistence",  # Associated MITRE ATT&CK tactic
        "protocol": "",  # Protocol used in the attack technique (empty here)
        "os": "Linux",  # Targeted operating systems
        "tips": [
            "Audit file creation and modification events within systemd directories.",
            "Compare results with a trusted system baseline.",
            "Use systemctl list-timers –all to view system-wide timers."
        ],  # Additional investigation and mitigation tips
        "data_sources": "Command: Command Execution, File: File Modification, Process: Process Creation, Scheduled Job: Scheduled Job Creation",  # List of relevant data sources
        "log_sources": [  # Logs necessary for detection, type should match data sources
            {"type": "Command", "source": "systemctl", "destination": ""},
            {"type": "File", "source": "/etc/systemd/system", "destination": ""},
            {"type": "File", "source": "/usr/lib/systemd/system/", "destination": ""}
        ],
        "source_artifacts": [  # Artifacts generated on the source machine
            {"type": "Systemd Timer", "location": "/etc/systemd/system/", "identify": "Malicious timer files"}
        ],
        "destination_artifacts": [  # Artifacts generated on the destination machine
            {"type": "Systemd Timer", "location": "/etc/systemd/system/", "identify": "Malicious timer files"}
        ],
        "detection_methods": [
            "Audit for systemd timer creation and modification.",
            "Use systemctl to check for unusual timer configurations.",
            "Compare service files with a known baseline."
        ],  # Techniques for identifying the attack
        "apt": ["SarathKumar Rajendran", "Trimble Inc"],  # APT groups known to use this technique
        "spl_query": [
            "| index=sysmon sourcetype=systemd | search *"
        ],  # Splunk queries to detect the technique
        "hunt_steps": [
            "Search for new systemd timer files in privileged systemd directories.",
            "Look for changes to systemd timers that do not correlate with known software."
        ],  # Steps to proactively hunt for threats
        "expected_outcomes": [
            "Identifying malicious systemd timer entries.",
            "Unusual systemd timer behavior."
        ],  # Expected results from detection/hunting
        "false_positive": "Legitimate system updates or administrative changes to systemd timers may trigger false positives.",  # Known false positives and how to handle them
        "clearing_steps": [
            "Remove malicious systemd timers from the systemd directories.",
            "Restore systemd timer files from a clean backup."
        ],  # Steps for remediation and clearing traces
        "mitre_mapping": [  # Next Mitre Technique that could be used after this one
            {"tactic": "Execution", "technique": "T1053", "example": "Create scheduled tasks for recurring execution."}
        ],
        "watchlist": [
            "Monitor systemd logs for unusual timer activity."
        ],  # Indicators to monitor for potential threats
        "enhancements": [
            "Improve detection by correlating with other event logs such as process creation and file modification."
        ],  # Suggested improvements to detection
        "summary": "Systemd timers can be abused by adversaries to schedule malicious tasks at system startup or on a recurring basis.",  # High-level summary of the technique
        "remediation": "Remove malicious systemd timers and restore from backup. Perform a full audit of systemd configurations.",  # Recommended actions to mitigate risk
        "improvements": "Implement tighter monitoring and auditing for systemd timer creation and modifications.",  # Suggested ways to improve detection and response
        "mitre_version": "16.1"  # MITRE ATT&CK version
    }
