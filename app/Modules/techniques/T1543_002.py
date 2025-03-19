def get_content():
    return {
        "id": "T1543.002",
        "url_id": "1543/002",
        "title": "Create or Modify System Process: Systemd Service",
        "description": "Adversaries may create or modify systemd services to execute malicious payloads for persistence or privilege escalation. Systemd is a widely used service manager on Linux, replacing legacy init systems like SysVinit and Upstart. Attackers can create new systemd service unit files or modify existing ones to execute commands at startup or during specific events.",
        "tags": ["Persistence", "Privilege Escalation", "Linux", "Systemd Service"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "Linux Systemd, Service Management",
        "os": ["Linux"],
        "tips": [
            "Monitor file creation and modification events in systemd service directories.",
            "Check systemd service files for unexpected modifications or new entries.",
            "Review systemctl command executions for unauthorized service modifications."
        ],
        "data_sources": "File Creation, File Modification, Service Creation, Command Execution, Process Creation",
        "log_sources": [
            {"type": "File", "source": "/etc/systemd/system/", "destination": "File System Logs"},
            {"type": "Command", "source": "Execution of systemctl", "destination": "Shell History"},
            {"type": "Service", "source": "Systemd Execution", "destination": "System Logs"}
        ],
        "source_artifacts": [
            {"type": "Systemd Unit File", "location": "/etc/systemd/system", "identify": "New or Modified Systemd Service"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "System Services", "identify": "Newly Created Systemd Service"}
        ],
        "detection_methods": [
            "Monitor for new or modified systemd service files.",
            "Analyze execution history of 'systemctl' commands.",
            "Check service unit files for malicious directives like 'ExecStart' and 'ExecStop'."
        ],
        "apt": ["Hildegard", "Fysbis", "Rocke", "Pupy", "Iron Tiger", "Sandworm", "TeamTNT", "TeleBots"],
        "spl_query": [
            "index=linux file_path=/etc/systemd/system/* | table _time, file_name, user, command"
        ],
        "hunt_steps": [
            "Review newly created or modified systemd service files.",
            "Analyze system logs for unexpected service executions.",
            "Check for unauthorized symbolic links in systemd service directories."
        ],
        "expected_outcomes": [
            "Detection of unauthorized systemd services.",
            "Identification of persistence mechanisms used by adversaries."
        ],
        "false_positive": "Legitimate systemd service modifications by administrators.",
        "clearing_steps": [
            "Remove unauthorized systemd service unit files.",
            "Disable and stop unauthorized systemd services.",
            "Investigate the origin of unauthorized service modifications."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "Modify Systemd Services", "example": "An attacker installs a systemd service for persistence."}
        ],
        "watchlist": ["Newly created or modified systemd services with unexpected execution paths."],
        "enhancements": ["Implement stricter monitoring of systemd service directories."],
        "summary": "Attackers may create or modify systemd services to establish persistence. Monitoring system logs and service modifications can help detect this technique.",
        "remediation": "Review and remove unauthorized systemd services. Strengthen monitoring and logging of service modifications.",
        "improvements": "Enable advanced logging for systemd service execution and file modifications."
    }
