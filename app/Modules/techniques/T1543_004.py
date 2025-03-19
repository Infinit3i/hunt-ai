def get_content():
    return {
        "id": "T1543.004",
        "url_id": "1543/004",
        "title": "Create or Modify System Process: Launch Daemon",
        "description": "Adversaries may create or modify Launch Daemons to execute malicious payloads as part of persistence. Launch Daemons are plist files used to interact with Launchd, the service management framework used by macOS. These daemons run at system startup with elevated privileges and do not require user interaction. Attackers can use this mechanism to maintain persistence and escalate privileges.",
        "tags": ["Persistence", "Privilege Escalation", "macOS", "Launch Daemon"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "macOS Launchd, System Daemons",
        "os": ["macOS"],
        "tips": [
            "Monitor for new files added to the `/Library/LaunchDaemons/` folder.",
            "Ensure Launch Daemons' 'Program' parameter points to signed executables.",
            "Use file integrity monitoring to detect modifications to Launch Daemon plist files."
        ],
        "data_sources": "File Creation, File Modification, Service Creation, Command Execution, Process Creation",
        "log_sources": [
            {"type": "File", "source": "Launch Daemon Directories", "destination": "File System Logs"},
            {"type": "Command", "source": "Execution of launchctl", "destination": "Shell History"},
            {"type": "Service", "source": "LaunchDaemon Execution", "destination": "System Logs"}
        ],
        "source_artifacts": [
            {"type": "Property List File", "location": "/Library/LaunchDaemons", "identify": "New or Modified LaunchDaemon .plist"}
        ],
        "destination_artifacts": [
            {"type": "System Daemon", "location": "LaunchDaemon Execution", "identify": "New Persistent Process"}
        ],
        "detection_methods": [
            "Monitor for new or modified LaunchDaemon .plist files.",
            "Detect execution of 'launchctl' commands related to Launch Daemons.",
            "Analyze persistence configurations with 'RunAtLoad' or 'ProgramArguments' settings."
        ],
        "apt": ["Dacls", "AppleJeus", "LoudMiner", "Green Lambert", "APT32", "COATHANGER", "XCSSET"],
        "spl_query": [
            "index=macos file_path=/Library/LaunchDaemons/* | table _time, file_name, user, command"
        ],
        "hunt_steps": [
            "Review new or modified Launch Daemon .plist files.",
            "Analyze execution history of 'launchctl' commands.",
            "Check for unauthorized Launch Daemon persistence mechanisms."
        ],
        "expected_outcomes": [
            "Detection of unauthorized Launch Daemons.",
            "Identification of persistence mechanisms used by adversaries."
        ],
        "false_positive": "Legitimate software updates installing new Launch Daemons.",
        "clearing_steps": [
            "Remove unauthorized Launch Daemon .plist files.",
            "Disable and delete unauthorized persistent processes.",
            "Investigate the origin of unauthorized Launch Daemons."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "Modify Launch Daemons", "example": "An attacker installs a Launch Daemon for persistence."}
        ],
        "watchlist": ["Newly created or modified Launch Daemon files with unexpected execution paths."],
        "enhancements": ["Implement stricter monitoring of Launch Daemon directories."],
        "summary": "Attackers may create or modify Launch Daemons to establish persistence. Monitoring system logs and file changes can help detect this technique.",
        "remediation": "Review and remove unauthorized Launch Daemons. Strengthen monitoring and logging of Launch Daemon modifications.",
        "improvements": "Enable advanced logging for Launch Daemon execution and file modifications."
    }
