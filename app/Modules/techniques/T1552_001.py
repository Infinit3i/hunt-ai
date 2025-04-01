def get_content():
    return {
        "id": "T1552.001",
        "url_id": "T1552/001",
        "title": "Unsecured Credentials: Credentials In Files",
        "description": "Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials.",
        "tags": ["credentials", "infostealer", "passwords", "lateral movement", "cloud", "container"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Containers, IaaS, Linux, Windows, macOS",
        "tips": [
            "Monitor access to configuration files containing credentials.",
            "Use DLP to detect and prevent plaintext password storage.",
            "Implement centralized credential management solutions."
        ],
        "data_sources": "Command, File, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File Access Times (MACB Timestamps)", "location": "User directories, config folders", "identify": "Files with embedded credentials"},
            {"type": "Sysmon Logs", "location": "Sysmon Event ID 1/11", "identify": "Process creation or file access to credential-storing files"}
        ],
        "destination_artifacts": [
            {"type": "File Access Times (MACB Timestamps)", "location": "Remote shares or copied VMs", "identify": "Files containing plaintext or encoded credentials"}
        ],
        "detection_methods": [
            "Command-line monitoring for password-related keywords",
            "File integrity monitoring for sensitive files",
            "Behavior-based detection of credential scraping tools"
        ],
        "apt": [
            "Trickbot", "MuddyWater", "Putter Panda", "Buckeye", "BlackEnergy",
            "Agent Tesla", "APT35", "APT34", "UNC2165", "RedCurl", "APT33",
            "Scattered Spider", "TA505", "Elephant Beetle", "Patchwork", "Anchor",
            "OilRig", "PYSA", "Azorult", "Stolen Pencil", "TeamTNT"
        ],
        "spl_query": [
            'index=main process_name=* password OR pwd OR credentials OR login\n| stats count by host, user, process_name, parent_process_name',
            'index=main file_path=* (passwd OR .env OR config OR credentials)\n| stats count by file_path, process_name, user'
        ],
        "hunt_steps": [
            "Search for scripts or tools accessing .env, config, or credential files.",
            "Review mounted volumes and storage for known credential dump paths.",
            "Hunt for command-line tools like `grep`, `find`, `cat` used in credential context."
        ],
        "expected_outcomes": [
            "Identification of adversary accessing or exfiltrating credential files",
            "Detection of password scraping behavior via logs"
        ],
        "false_positive": "Legitimate scripts or administrators accessing configuration files. Validate intent and user identity.",
        "clearing_steps": [
            "Remove plaintext credentials from any accessible file paths",
            "Rotate any credentials found exposed",
            "Audit file permissions and user access logs"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-credential-theft"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1027", "example": "Adversary may encode or obfuscate password files"},
            {"tactic": "Lateral Movement", "technique": "T1021.001", "example": "Using found credentials to access SMB shares"}
        ],
        "watchlist": [
            "*.env", "config.yml", "credentials.json", "docker-compose logs", "Group Policy Preferences XML"
        ],
        "enhancements": [
            "Enable Sysmon Event ID 1 (Process Creation) and 11 (File Create)",
            "Deploy honeypot files with fake credentials to trap access"
        ],
        "summary": "Adversaries search for insecurely stored credentials in files such as configs, backups, containers, and Group Policy Preferences.",
        "remediation": "Use secure vaulting solutions, avoid plaintext storage of passwords, monitor config file access, and restrict sensitive file permissions.",
        "improvements": "Correlate file access with user session and external transfer attempts. Improve detection coverage across cloud logs.",
        "mitre_version": "16.1"
    }
