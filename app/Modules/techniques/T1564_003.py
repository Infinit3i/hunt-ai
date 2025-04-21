def get_content():
    return {
        "id": "T1564.003",
        "url_id": "T1564/003",
        "title": "Hide Artifacts: Hidden Window",
        "description": "Adversaries may use hidden windows to conceal malicious activity from the plain sight of users. Techniques include launching scripts with hidden window flags, modifying application configurations to suppress visual cues, or using alternate desktop environments that are not visible to the user. These approaches allow malware or tools to operate silently in the background.",
        "tags": ["hidden window", "powershell hidden", "apple.awt.UIElement", "CreateDesktop", "stealth GUI"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor PowerShell for -WindowStyle Hidden",
            "Parse macOS plist files for 'apple.awt.UIElement' flags",
            "Use memory inspection to detect CreateDesktop() instances"
        ],
        "data_sources": "Command, File, Process, Script",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Script", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Script", "location": "Startup folders or temp paths", "identify": "Scripts using -WindowStyle Hidden"},
            {"type": "File", "location": "~/Library/Preferences/*.plist", "identify": "Presence of apple.awt.UIElement set to true"},
            {"type": "Process List", "location": "Memory and active sessions", "identify": "Suspicious explorer.exe instances in alternate desktops"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "Windows Task Manager or macOS Activity Monitor", "identify": "Processes running without a visible window"},
            {"type": "File", "location": "macOS plist configurations", "identify": "Dock suppression flags"},
            {"type": "Script", "location": "Hidden PowerShell or JScript execution logs", "identify": "Non-visible execution traces"}
        ],
        "detection_methods": [
            "Enable PowerShell logging and filter for -WindowStyle Hidden",
            "Detect usage of CreateDesktop() API via process injection or debugger inspection",
            "Monitor plist file modifications for apple.awt.UIElement"
        ],
        "apt": [
            "APT19", "APT28", "APT29", "APT32", "Gamaredon", "TrickBot", "Snip3", "InvisiMole", "Meteor", "Magic Hound", "Turla"
        ],
        "spl_query": [
            "index=winlog EventCode=4104 \n| search ScriptBlockText=*WindowStyle Hidden* \n| stats count by UserID, ScriptBlockText",
            "index=osquery OR index=mac_logs \n| search FilePath=*plist* AND Contents=*apple.awt.UIElement* \n| stats count by FilePath, Contents",
            "index=sysmon EventCode=1 \n| search CommandLine=*CreateDesktop* \n| stats count by Image, ParentImage, CommandLine"
        ],
        "hunt_steps": [
            "Search for use of -WindowStyle Hidden in PowerShell logs",
            "Review plist files on macOS for UI suppression flags",
            "Analyze running processes with unusual parent/child relationships"
        ],
        "expected_outcomes": [
            "Detection of stealth script execution with hidden windows",
            "Identification of macOS applications masked from the Dock",
            "Uncovering alternate desktop environments or hVNC sessions"
        ],
        "false_positive": "Some legitimate administrative scripts or background apps may use hidden window styles. Validate behavior and source before escalation.",
        "clearing_steps": [
            "Remove startup scripts that use hidden window flags",
            "Reset or delete plist entries modifying UI visibility",
            "Terminate alternate desktop explorer.exe sessions manually"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059.001", "example": "PowerShell scripts with hidden execution windows"},
            {"tactic": "Defense Evasion", "technique": "T1140", "example": "Obfuscation of code running in invisible GUIs"}
        ],
        "watchlist": [
            "CommandLine contains -WindowStyle Hidden",
            "Plist files updated with UIElement flags",
            "CreateDesktop API calls linked to secondary explorer.exe instances"
        ],
        "enhancements": [
            "Enable full command-line process auditing",
            "Implement plist monitoring on macOS endpoints",
            "Use behavioral analytics to flag GUI-suppressed execution"
        ],
        "summary": "This technique leverages operating system features to suppress window visibility for malicious tools, helping adversaries avoid user suspicion and maintain stealth operations.",
        "remediation": "Investigate scripts or binaries executed with GUI-suppressing flags, terminate hidden desktop sessions, and enforce endpoint controls to restrict hidden execution behaviors.",
        "improvements": "Develop alerting rules for hidden process execution and maintain integrity checks on plist and startup files across systems.",
        "mitre_version": "16.1"
    }
