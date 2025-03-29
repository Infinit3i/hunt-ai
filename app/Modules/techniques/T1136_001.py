def get_content():
    return {
        "id": "T1136.001",
        "url_id": "T1136/001",
        "title": "Create Account: Local Account",
        "description": "Adversaries may create a local account to maintain access to victim systems. Local accounts are configured for use by users, remote support, services, or administration on a single system. Attackers may use the `net user /add` command on Windows or `dscl -create` on macOS to create local accounts. Kubernetes clusters and network devices can also be targeted using `kubectl` and `username` commands, respectively.",
        "tags": ["Persistence", "Local Account", "User Account Creation"],
        "tactic": "Persistence",
        "protocol": "Local Authentication, SSH, SMB",
        "os": ["Windows", "Linux", "macOS", "Containers", "Network"],
        "tips": [
            "Monitor for processes and command-line parameters associated with local account creation.",
            "Event ID 4720 is generated when a user account is created on a Windows system.",
            "Perform regular audits of local system accounts to detect suspicious accounts.",
            "For network devices, collect AAA logging to monitor account creations."
        ],
        "data_sources": "User Account, Process Creation, System Logs, Network Logs",
        "log_sources": [
            {"type": "Windows Security", "source": "Event ID 4720", "destination": "Local System"},
            {"type": "Process", "source": "Command Execution", "destination": "System Logs"},
            {"type": "Network", "source": "AAA Logs", "destination": "Network Devices"}
        ],
        "source_artifacts": [
            {"type": "Event Log", "location": "Windows Security Log", "identify": "Event ID 4720"}
        ],
        "destination_artifacts": [
            {"type": "Account Object", "location": "Local System", "identify": "New Local Account"}
        ],
        "detection_methods": [
            "Monitor Event ID 4720 for local account creation.",
            "Detect `net user /add` and `dscl -create` command execution.",
            "Correlate new account creation with process execution logs."
        ],
        "apt": ["ZxShell", "Chafer", "Dust Storm", "Pupy", "APT41", "Hildegard", "Calisto", "GoldenSpy", "Daggerfly", "TeamTNT", "UNC2165", "Iranian Threat Actor Trends", "FIN12", "HiddenWasp", "PowerShell Empire", "Elephant Beetle", "Darkgate", "TA505", "Flame", "Pay2Kitten", "Leafminer", "APT35", "CARBANAK", "SMOKEDHAM"],
        "spl_query": [
            "index=windows EventCode=4720 | table _time, Account_Name, Caller_User_Name, ComputerName"
        ],
        "hunt_steps": [
            "Review newly created local accounts.",
            "Check for unauthorized account creation.",
            "Analyze command-line history for account creation commands."
        ],
        "expected_outcomes": [
            "Identification of unauthorized local accounts.",
            "Detection of attacker persistence mechanisms."
        ],
        "false_positive": "Legitimate local account creation by IT administrators.",
        "clearing_steps": [
            "Disable and delete unauthorized local accounts.",
            "Review and revoke unnecessary permissions on local accounts.",
            "Investigate the source of unauthorized account creation."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "Create Account", "example": "An attacker creates a new local account for persistence."}
        ],
        "watchlist": ["Newly created local accounts with unexpected privileges."],
        "enhancements": ["Implement stricter auditing policies for local account creation."],
        "summary": "Attackers may create local accounts to maintain persistent access. Monitoring Event ID 4720 and command execution logs can help detect this technique.",
        "remediation": "Review and remove unauthorized accounts. Enforce strict account creation policies.",
        "improvements": "Enable advanced logging for user account modifications on local systems."
    }
