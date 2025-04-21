def get_content():
    return {
        "id": "T1647",
        "url_id": "T1647",
        "title": "Plist File Modification",
        "description": "Adversaries may modify property list (plist) files on macOS systems to enable persistence, defense evasion, or execution of malicious behaviors. Plist files store application and system configuration as structured metadata. By altering values within these files, adversaries can influence how the system handles application behavior. Common modifications include hiding execution, establishing persistence through LaunchAgents or LaunchDaemons, and injecting environment variables to enable dynamic linker hijacking.",
        "tags": ["macOS", "plist", "persistence", "LSUIElement", "LaunchAgent", "LaunchDaemon", "defense evasion", "LSEnvironment"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "macOS",
        "tips": [
            "Track changes to `~/Library/Preferences/*.plist` and `~/LaunchAgents/*.plist`.",
            "Detect suspicious use of `defaults write`, `plutil`, or `nano` to edit plist files.",
            "Correlate plist edits with the start of new background processes."
        ],
        "data_sources": "Command: Command Execution, File: File Modification, Process: Process Creation",
        "log_sources": [
            {"type": "File", "source": "Unified Logs, File Integrity Monitoring", "destination": ""},
            {"type": "Command", "source": "Terminal Command History, Syslog", "destination": ""},
            {"type": "Process", "source": "Process Monitor, Endpoint Telemetry", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Plist File", "location": "~/Library/Preferences/", "identify": "Modified user preferences to enable hidden or persistent apps"},
            {"type": "Plist File", "location": "~/LaunchAgents/", "identify": "Auto-run agents executing on login"},
            {"type": "Plist File", "location": "/Applications/<AppName>.app/Contents/Info.plist", "identify": "Hidden UI applications or manipulated environment settings"}
        ],
        "destination_artifacts": [
            {"type": "Background Execution", "location": "System Tray, Process List", "identify": "Apps running without visible windows"},
            {"type": "Persistence", "location": "LaunchAgent Daemons", "identify": "Apps re-executed across sessions"},
            {"type": "Environment Variables", "location": "Application Plists", "identify": "Use of LSEnvironment for hijacking"}
        ],
        "detection_methods": [
            "Monitor modifications to key plist files like `Info.plist`, `com.apple.dock.plist`, and LaunchAgent entries.",
            "Detect sudden file modifications followed by process creation from `~/Library/Scripts`.",
            "Alert on the presence of new background tasks or GUI-less apps added via `LSUIElement` key."
        ],
        "apt": [
            "XCSSET: Xcode project injecting malicious plist to persist and control GUI elements",
            "Cuckoo Stealer: Recently observed abusing plist files for evasion in 2024"
        ],
        "spl_query": "index=macos sourcetype=fs_monitor \n| search file_path=*plist* AND (file_action=modified OR file_action=created) \n| stats count by file_path, user",
        "spl_rule": "https://research.splunk.com/detections/tactics/defense-evasion/",
        "elastic_rule": "https://grep.app/search?f.repo=elastic%2Fdetection-rules&q=T1647",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1647",
        "hunt_steps": [
            "List plist files modified within the last 7 days in `~/Library/Preferences/` and `~/LaunchAgents/`.",
            "Search for use of `plutil` or `defaults` targeting application or dock settings.",
            "Correlate plist file changes with background process launches.",
            "Look for new keys added to `Info.plist` that define execution behavior like `LSUIElement` or `LSEnvironment`."
        ],
        "expected_outcomes": [
            "Detection of plist modification for persistence or hiding malware.",
            "Termination of background processes launched through edited plist files.",
            "Hardening of plist-based permissions and reduction of tampering risk."
        ],
        "false_positive": "Administrators or application installers may legitimately update plist files during customization or installation. Contextual correlation is necessary.",
        "clearing_steps": [
            "Restore plist file from known-good backup.",
            "Remove unauthorized LaunchAgents or scripts from `~/Library/Preferences/` and `~/Library/Scripts/`.",
            "Terminate malicious background processes or uninstall tampered applications."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1647 (Plist File Modification)", "example": "Editing `LSUIElement` to hide malicious applications from the user interface."}
        ],
        "watchlist": [
            "Monitor all plist file modifications outside normal software installation events.",
            "Track new entries in LaunchAgent and LaunchDaemon folders.",
            "Watch for background processes tied to new plist-based environment variables."
        ],
        "enhancements": [
            "Implement file integrity monitoring on key plist directories.",
            "Log all plist writes using `fs_usage` or Unified Logs.",
            "Apply read-only permissions where feasible to critical plist files."
        ],
        "summary": "Plist File Modification allows adversaries on macOS to hide processes, maintain persistence, or alter application behavior by modifying configuration files. These changes are subtle and often go unnoticed without robust file monitoring.",
        "remediation": "Review, validate, and restore modified plist files. Remove LaunchAgents or other artifacts introduced by adversaries.",
        "improvements": "Apply tighter controls on plist file edit permissions. Improve logging of LaunchAgent modifications and auto-run behavior.",
        "mitre_version": "16.1"
    }
