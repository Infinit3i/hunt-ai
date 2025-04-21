def get_content():
    return {
        "id": "T1569.001",
        "url_id": "T1569/001",
        "title": "System Services: Launchctl",
        "description": "Adversaries may abuse the `launchctl` utility on macOS to execute malicious commands or launch programs. `launchctl` is a command-line interface to `launchd`, the service management framework used by macOS to manage Launch Agents and Launch Daemons. Common commands include `launchctl load`, `launchctl unload`, and `launchctl start`.\n\nThis technique is often used to persist payloads or execute malicious services. The adversary can leverage `launchctl load -w` to enable execution of a `.plist` configuration that defines malicious behavior. Suspicious behaviors may include `.plist` files with paths pointing to writable or temporary directories such as `/tmp` or `/Users/Shared`.\n\nWhen leveraged maliciously, `launchctl` can assist in stealthy execution by masking under legitimate macOS service management mechanisms.",
        "tags": ["macos", "persistence", "execution", "launchd", "launchctl", "launchagents", "launchdaemons"],
        "tactic": "Execution",
        "protocol": "N/A",
        "os": "macOS",
        "tips": [
            "Track newly created or modified `.plist` files inside `/Library/LaunchAgents` and `/Library/LaunchDaemons`.",
            "Correlate `launchctl` command usage with suspicious executable paths or sudden network activity.",
            "Pay attention to services loading from non-standard directories like `/tmp`, `/Users/Shared`, or user-writable paths."
        ],
        "data_sources": "Command Execution, File Modification, Process Creation, Service Creation",
        "log_sources": [
            {"type": "Command Execution", "source": "Unified Logs (`log show --predicate`)", "destination": ""},
            {"type": "File Modification", "source": "Filesystem Events (FSEvents, audit logs)", "destination": ""},
            {"type": "Process Creation", "source": "Endpoint Security Framework / EDR tools", "destination": ""},
            {"type": "Service Creation", "source": "Monitoring `.plist` loading and `launchd` activity", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Launchctl Command", "location": "Terminal/Script", "identify": "`launchctl load -w <path>`"},
            {"type": "PLIST File Created", "location": "/Library/LaunchAgents or LaunchDaemons", "identify": "Suspicious or new `.plist` files"}
        ],
        "destination_artifacts": [
            {"type": "Service Execution", "location": "launchd", "identify": "Execution of plist-configured payload"},
            {"type": "Modified File Path", "location": "/tmp or /Users/Shared", "identify": "Executable or service configuration pointing to insecure paths"}
        ],
        "detection_methods": [
            "Monitor the creation or modification of `.plist` files associated with Launch Agents/Daemons.",
            "Track usage of `launchctl` and correlate with changes in running services or execution paths.",
            "Watch for launch of services whose executable resides in non-default or writable directories."
        ],
        "apt": ["LoudMiner", "AppleJeus", "xcsset", "Calisto"],
        "spl_query": [
            "index=macos sourcetype=macos_logs \"launchctl\" OR \"launchd\" \n| search command=\"load\" OR command=\"start\" \n| stats count by user, command, file_path"
        ],
        "hunt_steps": [
            "Search for `launchctl` command usage with unusual arguments or from non-standard users.",
            "Identify recently modified `.plist` files in LaunchAgents/LaunchDaemons paths.",
            "Check for persistence mechanisms via services pointing to `/tmp` or external drives.",
            "Cross-reference created services with known malware behaviors or threat intel IOCs."
        ],
        "expected_outcomes": [
            "Launchctl Abuse Detected: Escalate for removal of malicious `.plist`, isolate system.",
            "No Malicious Activity Found: Continue passive monitoring for launch service abuse."
        ],
        "false_positive": "Legitimate developers or system administrators may use `launchctl` to manage services. Validate with user roles and known admin scripts.",
        "clearing_steps": [
            "Unload suspicious Launch Agents/Daemons using `launchctl unload`.",
            "Delete associated `.plist` files after unloading.",
            "Rebuild launch services database if tampered."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1569.001 (Launchctl)", "example": "Adversary uses `launchctl load` to execute a malicious daemon."},
            {"tactic": "Persistence", "technique": "T1543.004 (Launch Daemon)", "example": "Persistence via malicious daemon setup."},
            {"tactic": "Privilege Escalation", "technique": "T1543.004 (Launch Daemon)", "example": "Adversary sets system-wide daemon to escalate privileges at boot."}
        ],
        "watchlist": [
            "Detect usage of `launchctl` pointing to writable or temporary directories.",
            "Track new `.plist` files created in LaunchAgents or LaunchDaemons folders.",
            "Monitor interactive shell commands loading launch services."
        ],
        "enhancements": [
            "Use EDR tools to block unauthorized `launchctl` usage.",
            "Harden user permissions to prevent arbitrary plist creation.",
            "Implement file integrity monitoring on system plist paths."
        ],
        "summary": "Launchctl abuse allows adversaries to execute or persist on macOS systems using native service management. Tracking plist modifications and launchctl activity helps detect this behavior.",
        "remediation": "Unload malicious services via `launchctl`, delete related plist files, and review affected user sessions.",
        "improvements": "Automate detection of launchctl abuse via EDRs and system integrity monitoring tools. Enforce read-only system partitioning where feasible.",
        "mitre_version": "16.1"
    }
