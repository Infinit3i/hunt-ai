def get_content():
    return {
        "id": "T1546.004",
        "url_id": "T1546/004",
        "title": "Event Triggered Execution: Unix Shell Configuration Modification",
        "description": "Adversaries may establish persistence by inserting malicious commands into Unix or macOS shell configuration files that are executed when a shell session starts or terminates.",
        "tags": ["bashrc", "bash_profile", "zshrc", "shell", "macOS", "linux", "startup", "logout", "persistence"],
        "tactic": "Persistence",
        "protocol": "",
        "os": "Linux, macOS",
        "tips": [
            "Monitor user shell configuration files for suspicious or non-standard commands",
            "Use file integrity monitoring on /etc/profile, /etc/zshenv, and related files",
            "Inspect network or file-based activity during shell initialization"
        ],
        "data_sources": "Command, File, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Registry Hives", "location": "~/.bashrc, ~/.bash_profile, ~/.zshrc, /etc/profile", "identify": "Inserted shell commands or paths to payloads"},
            {"type": "File Access Times (MACB Timestamps)", "location": "/etc/profile.d/, ~/.bash_logout, ~/.zlogout", "identify": "Modified logout routines for triggering persistence"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Compare modified shell profile files against known-good baselines",
            "Alert on commands that initiate network connections or execute binaries",
            "Correlate shell startup with execution of unexpected programs"
        ],
        "apt": [],
        "spl_query": [
            'index=linux_logs sourcetype=linux_shell_config file_path IN ("~/.bashrc", "~/.bash_profile", "/etc/profile", "~/.zshrc", "/etc/zshrc") command="*wget*" OR command="*curl*" OR command="*nc*"',
            'index=macos_logs sourcetype=esf_file_monitor event_type=MODIFY file_path IN ("/etc/zprofile", "/etc/zshenv", "/etc/profile.d/*")'
        ],
        "hunt_steps": [
            "Scan for inserted commands in ~/.bashrc, ~/.bash_profile, ~/.zshrc, and ~/.zlogout",
            "Search for signs of persistence in logout-triggered files like ~/.bash_logout",
            "Audit system-wide profile directories like /etc/profile.d/"
        ],
        "expected_outcomes": [
            "Identification of persistence via shell initialization and logout scripts",
            "Detection of suspicious commands within shell config files"
        ],
        "false_positive": "Custom user configurations may include legitimate but unusual commands. Validate with user or system admin before action.",
        "clearing_steps": [
            "sed -i '/malicious_command/d' ~/.bashrc ~/.bash_profile ~/.zshrc ~/.bash_logout ~/.zlogout",
            "rm -f ~/.malicious_payload.sh",
            "source /etc/profile"
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1059.004", "example": "Shell startup scripts launching a malicious command during interactive session"}
        ],
        "watchlist": [
            "Modifications to /etc/profile.d/ or ~/.bash_logout",
            "Unexpected command execution at login or logout"
        ],
        "enhancements": [
            "Deploy file integrity monitoring to shell config directories",
            "Log shell initialization with command auditing tools like auditd or ESF"
        ],
        "summary": "Unix and macOS shell configuration files (like .bashrc, .bash_profile, .zshrc) can be modified by adversaries to establish persistence or trigger malicious execution during shell login or logout.",
        "remediation": "Remove unauthorized commands from shell initialization files. Reload shell environments and restart user sessions if necessary.",
        "improvements": "Restrict write access to critical shell config files and use version control for change tracking.",
        "mitre_version": "16.1"
    }
