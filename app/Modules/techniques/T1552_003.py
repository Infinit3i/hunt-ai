def get_content():
    return {
        "id": "T1552.003",
        "url_id": "T1552/003",
        "title": "Unsecured Credentials: Bash History",
        "description": "Adversaries may search the bash command history on compromised systems for insecurely stored credentials.",
        "tags": ["credentials", "bash", "history", "infostealer", "linux", "macos"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Linux, macOS",
        "tips": [
            "Encourage users not to type sensitive information directly into command-line arguments.",
            "Use shell wrappers or credential managers to handle secrets securely.",
            "Set HISTCONTROL=ignorespace or HISTIGNORE for sensitive commands."
        ],
        "data_sources": "Command, File",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Bash History", "location": "~/.bash_history", "identify": "Presence of passwords or usernames in command arguments"},
            {"type": "File Access Times (MACB Timestamps)", "location": "~/.bash_history", "identify": "Timestamp changes indicating viewing or editing"}
        ],
        "destination_artifacts": [
            {"type": "Memory Dumps", "location": "/tmp, /dev/shm", "identify": "Dumped history or password data"},
            {"type": "File Access Times (MACB Timestamps)", "location": "Shared storage if used", "identify": "Copied bash history from another system"}
        ],
        "detection_methods": [
            "Monitor file reads or access to `.bash_history` directly",
            "Detect command-line usage of `cat`, `less`, or `grep` targeting `.bash_history`",
            "Monitor user shell environments for insecure history settings"
        ],
        "apt": [
            "Kinsing"
        ],
        "spl_query": [
            'index=linux sourcetype=linux_audit file_path="*/.bash_history" command="cat" OR command="less" OR command="grep"\n| stats count by host, user, command',
            'index=linux bash_command="*password*" source="/home/*/.bash_history"\n| stats count by user, bash_command, _time'
        ],
        "hunt_steps": [
            "Search for command-line access to `.bash_history` via tools like `cat`, `grep`, or `less`.",
            "Look for sensitive strings like `password`, `token`, `secret` inside `.bash_history`.",
            "Review user shell configuration (`.bashrc`, `.profile`) for HISTCONTROL settings."
        ],
        "expected_outcomes": [
            "Detection of adversary reading `.bash_history`",
            "Discovery of exposed credentials saved in shell history"
        ],
        "false_positive": "Legitimate users occasionally review their own history; correlation with other suspicious behavior is recommended.",
        "clearing_steps": [
            "Clear `.bash_history` using `history -c` and remove file if needed.",
            "Reconfigure shell with secure history options (e.g., HISTCONTROL=ignorespace).",
            "Rotate any credentials exposed in command history."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-credential-theft"
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1087", "example": "Reading user-specific command histories for context"},
            {"tactic": "Defense Evasion", "technique": "T1070.003", "example": "Clearing bash history after collecting credentials"}
        ],
        "watchlist": [
            ".bash_history", "history -c", "cat ~/.bash_history", "grep password ~/.bash_history"
        ],
        "enhancements": [
            "Deploy auditd rules or EDR agents to track access to shell history files",
            "Implement shell wrappers or audit logging to mask or secure sensitive inputs"
        ],
        "summary": "Adversaries may abuse bash history files to retrieve previously typed credentials exposed through command-line usage.",
        "remediation": "Train users to avoid passing secrets in commands, use secure alternatives, and configure shell settings securely.",
        "improvements": "Implement bash history monitoring via auditd, and deploy credential hygiene training for Linux users.",
        "mitre_version": "16.1"
    }
