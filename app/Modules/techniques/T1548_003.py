def get_content():
    return {
        "id": "T1548.003",
        "url_id": "1548/003",
        "title": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "description": (
            "Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges. They may execute commands "
            "as other users or spawn processes with higher privileges. Within Linux and macOS systems, sudo allows users to perform "
            "commands from terminals with elevated privileges and to control who can perform these commands on the system. "
            "Adversaries can abuse sudo caching, timestamp manipulation, or misconfigured sudoers files to bypass authentication."
        ),
        "tags": ["Privilege Escalation", "Defense Evasion", "Linux Exploitation", "macOS Exploitation"],
        "tactic": "Defense Evasion, Privilege Escalation",
        "protocol": "Unix Privilege Management",
        "os": "Linux, macOS",
        "tips": [
            "Monitor the sudoers file for unauthorized modifications (`/etc/sudoers`).",
            "Check for processes modifying `/var/db/sudo`, as it tracks sudo session timestamps.",
            "Audit sudo commands using `auditd` to detect unauthorized privilege escalation.",
            "Use the `LOG_INPUT` and `LOG_OUTPUT` directives in `/etc/sudoers` to log all sudo activity."
        ],
        "data_sources": "Command: Command Execution, File: File Modification, Process: Process Creation, Process: Process Metadata",
        "log_sources": [
            {"type": "File Modification", "source": "Linux/macOS Audit Logs", "destination": "SIEM"},
            {"type": "Command Execution", "source": "Process Monitoring", "destination": "Endpoint Security"},
        ],
        "source_artifacts": [
            {"type": "Sudoers File", "location": "/etc/sudoers", "identify": "Check for NOPASSWD entries"},
            {"type": "Sudo Session Cache", "location": "/var/db/sudo", "identify": "Monitor for timestamp manipulations"},
        ],
        "destination_artifacts": [
            {"type": "Process Execution", "location": "/var/log/auth.log", "identify": "Processes executed via sudo"},
        ],
        "detection_methods": [
            "Monitor sudo commands and track changes to `/etc/sudoers`.",
            "Detect sudo timestamp manipulation by monitoring `/var/db/sudo`.",
            "Check for unexpected privilege escalations in process logs.",
        ],
        "apt": ["Cobalt Strike", "OSX.Dok malware"],
        "spl_query": [
            "index=linux_logs sourcetype=auditd \n| search sudo \n| stats count by user, process_name, command",
        ],
        "hunt_steps": [
            "Check `/etc/sudoers` for insecure configurations (`NOPASSWD: ALL`).",
            "Review `/var/db/sudo` for unusual timestamp changes.",
            "Analyze sudo execution logs for unauthorized commands.",
        ],
        "expected_outcomes": [
            "Privilege Escalation Detected: Investigate unauthorized sudo executions.",
            "No Malicious Activity Found: Improve sudo policies and monitoring mechanisms.",
        ],
        "false_positive": "Some administrators may configure sudo caching for convenience; verify intent before alerting.",
        "clearing_steps": [
            "Revoke unnecessary sudo privileges and disable sudo caching if not needed.",
            "Reset `/etc/sudoers` to a secure state and audit permissions.",
            "Ensure users require passwords for privilege escalation and remove insecure NOPASSWD entries.",
        ],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1548.003", "example": "Exploiting sudo misconfigurations to elevate privileges."},
        ],
        "watchlist": [
            "Monitor sudo commands for privilege escalation attempts.",
            "Detect changes to `/etc/sudoers` that enable NOPASSWD for users.",
            "Analyze process creation logs for sudo-spawned processes with unexpected privileges.",
        ],
        "enhancements": [
            "Restrict sudo access and enforce least privilege principles.",
            "Implement sudo logging and periodic reviews of `/etc/sudoers` configurations.",
        ],
        "summary": "Adversaries may abuse sudo caching or misconfigured sudoers files to escalate privileges without requiring a password.",
        "remediation": "Monitor and restrict sudo usage, review sudoers configurations, and enforce strong authentication policies.",
        "improvements": "Improve logging and auditing mechanisms to detect and prevent unauthorized privilege escalations.",
    }
