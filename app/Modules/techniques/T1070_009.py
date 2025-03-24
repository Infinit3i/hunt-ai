def get_content():
    return {
        "id": "T1070.009",
        "url_id": "T1070/009",
        "title": "Indicator Removal: Clear Persistence",
        "description": "Adversaries may clear artifacts associated with previously established persistence on a host system to remove evidence of their activity. This may involve various actions, such as removing services, deleting executables, modifying the registry or plist files, or deleting created accounts.",
        "tags": ["defense evasion", "persistence", "registry", "user accounts", "scheduled tasks", "linux", "macos", "windows"],
        "tactic": "defense-evasion",
        "protocol": "",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Track account creations and deletions over time",
            "Alert on deletion of known persistence services or scheduled tasks",
            "Correlate process activity with removal of registry or plist entries"
        ],
        "data_sources": "Command, File, Process, Scheduled Job, User Account, Windows Registry",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Scheduled Job", "source": "", "destination": ""},
            {"type": "User Account", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Windows Registry", "location": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "identify": "Registry-based persistence keys"},
            {"type": "Scheduled Job", "location": "C:\\Windows\\System32\\Tasks", "identify": "Malicious scheduled tasks"},
            {"type": "File", "location": "C:\\Users\\<user>\\AppData\\Roaming", "identify": "Dropped malware used for persistence"},
            {"type": "User Account", "location": "/etc/passwd (Linux) or SAM (Windows)", "identify": "Malicious created accounts"},
            {"type": "File", "location": "~/Library/LaunchAgents/", "identify": "Plist files for persistence on macOS"}
        ],
        "destination_artifacts": [
            {"type": "", "location": "", "identify": ""}
        ],
        "detection_methods": [
            "Monitor for deletion of known persistence artifacts",
            "Alert on the removal of accounts shortly after creation",
            "Detect process creation tied to registry or plist modifications",
            "Track removal of scheduled jobs and service entries"
        ],
        "apt": ["LazyScripter", "Team9", "GrimAgent", "Agrius", "MCMD", "RTM", "Pillowmint", "Dust Storm", "njRAT", "Raspberry Robin"],
        "spl_query": [
            "index=wineventlog EventCode=4726 \n| stats count by TargetUserName, SubjectUserName, ComputerName",
            "index=sysmon EventCode=13 registry_path=\"*Run*\" action=deleted \n| stats count by host, user, registry_path",
            "index=sysmon EventCode=1 Image=\"*schtasks.exe\" CommandLine=\"*/Delete*\" \n| table _time, user, CommandLine",
            "index=sysmon EventCode=11 TargetFilename=\"*.plist\" action=deleted \n| stats count by host, TargetFilename"
        ],
        "hunt_steps": [
            "Identify systems with recent deletions of persistence-related registry/plist entries",
            "Review logs for user account deletions and their prior activity",
            "Correlate file deletions with startup folders or persistence paths",
            "Search for suspicious cleanup commands (e.g., schtasks /delete, reg delete)"
        ],
        "expected_outcomes": [
            "Malicious persistence mechanisms removed before detection",
            "Reduced visibility into earlier stages of compromise",
            "Missing registry keys, user accounts, or startup files"
        ],
        "false_positive": "Legitimate administrators or cleanup tools may perform similar actions. Cross-reference with change control tickets or IT maintenance windows.",
        "clearing_steps": [
            "reg delete HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\<malware_entry> /f",
            "schtasks /Delete /TN \"<task_name>\" /F",
            "rm ~/Library/LaunchAgents/<malicious>.plist",
            "net user <malicious_account> /delete",
            "del C:\\Users\\<user>\\AppData\\Roaming\\<malicious_file>.exe"
        ],
        "mitre_mapping": [
            {"tactic": "persistence", "technique": "T1543.003", "example": "Service-based persistence removed post-compromise"},
            {"tactic": "defense-evasion", "technique": "T1112", "example": "Registry entries modified or deleted to clean up"},
            {"tactic": "persistence", "technique": "T1136", "example": "Removal of created user accounts used for persistence"}
        ],
        "watchlist": [
            "Deletion of persistence registry keys",
            "Account deletions within 24 hours of creation",
            "Removal of scheduled tasks outside normal patch windows"
        ],
        "enhancements": [
            "Enable registry key auditing on known persistence paths",
            "Implement alerts for scheduled task deletions",
            "Baseline system startup entries for change detection"
        ],
        "summary": "This technique involves clearing persistence mechanisms such as registry entries, scheduled jobs, and user accounts to evade detection. Adversaries may clean up to avoid analysis or to prevent duplicate execution.",
        "remediation": "Audit systems for persistence mechanisms and monitor for abrupt deletions. Rebuild affected hosts where applicable and review authentication logs.",
        "improvements": "Log registry and task deletions. Create alerts for unexpected user account removals. Maintain baseline of known services, jobs, and persistence locations.",
        "mitre_version": "16.1"
    }
