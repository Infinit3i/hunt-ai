def get_content():
    return {
        "id": "T1546.005",
        "url_id": "T1546/005",
        "title": "Event Triggered Execution: Trap",
        "description": "Adversaries may establish persistence by executing malicious content triggered by an interrupt signal using the trap command.",
        "tags": ["trap", "persistence", "signal", "bash", "event-triggered"],
        "tactic": "Persistence",
        "protocol": "",
        "os": "Linux, macOS",
        "tips": [
            "Monitor scripts and config files for unusual trap commands",
            "Look for overly broad signal handling (e.g., multiple signals triggering one payload)",
            "Review user shell profiles (.bashrc, .bash_profile, etc.) for trap usage"
        ],
        "data_sources": "Command, File, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File Access Times (MACB Timestamps)", "location": "~/.bashrc, ~/.bash_profile, /etc/profile", "identify": "trap command usage and modification time"},
            {"type": "Shell History", "location": "~/.bash_history", "identify": "trap command insertions or executions"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Analyze shell initialization scripts for trap commands",
            "Identify commands set to execute on signals like SIGINT (Ctrl+C)",
            "Detect unexpected processes executed during signal handling"
        ],
        "apt": [],
        "spl_query": [
            'index=linux_logs sourcetype=linux_bash history="*trap*" OR command="*trap*"'
        ],
        "hunt_steps": [
            "Search for trap usage in common shell startup files",
            "Correlate shell interruptions with unexpected process creation",
            "Check for persistence via modified signal handlers"
        ],
        "expected_outcomes": [
            "Detection of trap-based persistence mechanisms",
            "Identification of suspicious commands executed through signal handling"
        ],
        "false_positive": "Legitimate use of trap for error handling or cleanup in scripts. Validate intent and user activity context.",
        "clearing_steps": [
            "sed -i '/trap/d' ~/.bashrc",
            "sed -i '/trap/d' ~/.bash_profile",
            "rm -f ~/.malicious_script.sh",
            "kill -9 $(pgrep -f malicious_process)"
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1059.004", "example": "Execution of trap-registered payloads via Bash shell"}
        ],
        "watchlist": [
            "trap '...' INT EXIT",
            "*.sh files containing trap commands with obfuscated payloads"
        ],
        "enhancements": [
            "Flag shell scripts registering trap handlers for signals like SIGINT, SIGTERM",
            "Implement file integrity monitoring on .bashrc, .profile, and other startup files"
        ],
        "summary": "The `trap` command can be abused to maintain persistence by executing malicious commands when specific signals (like Ctrl+C) are received in a Unix shell.",
        "remediation": "Remove unauthorized trap commands from shell configuration files and monitor reappearance. Educate users on secure shell scripting practices.",
        "improvements": "Enable audit logging for shell command execution and modifications to shell initialization files.",
        "mitre_version": "16.1"
    }
