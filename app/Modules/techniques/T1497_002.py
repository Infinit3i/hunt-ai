def get_content():
    return {
        "id": "T1497.002",
        "url_id": "T1497/002",
        "title": "Virtualization/Sandbox Evasion: User Activity Based Checks",
        "description": "Adversaries may employ various user activity checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox.",
        "tags": ["defense evasion", "discovery", "user behavior", "vm evasion", "sandbox detection", "anti-analysis"],
        "tactic": "Defense Evasion, Discovery",
        "protocol": "",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Deploy decoy user interaction artifacts such as mouse movement simulators or synthetic browser histories.",
            "Use behavioral sandboxing that emulates human-like delays, clicks, and UI interaction.",
            "Monitor for long idle times followed by sudden malicious execution, suggesting activity gating.",
            "Analyze macro-triggered malware for user-dependent behavior branching logic."
        ],
        "data_sources": "Command, Process",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "Process", "source": "Process Creation", "destination": ""},
            {"type": "Process", "source": "OS API Execution", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Clipboard Data", "location": "User Session", "identify": "Access or queries into clipboard suggesting user interaction testing"},
            {"type": "Browser History", "location": "User Profile", "identify": "Attempt to read Chrome, Firefox, or Edge history to verify user activity"},
            {"type": "UserAssist", "location": "NTUSER.DAT", "identify": "Enumerated counts of opened applications to judge environment authenticity"},
            {"type": "Registry Hives", "location": "NTUSER.DAT", "identify": "Search for presence of user personalization or file opening history"},
            {"type": "Recent Files", "location": "AppData, %USERPROFILE%", "identify": "Enumeration of recent documents to determine user behavior"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Analyze malware with long delays or requiring user-triggered logic (e.g., double-click, document close).",
            "Monitor for access to browser artifacts or user environment info within seconds of initial execution.",
            "Detect processes that terminate or delay indefinitely in low-interaction environments.",
            "Trace uncommon API calls that correlate to user interaction detection (e.g., GetCursorPos, GetLastInputInfo)."
        ],
        "apt": ["FIN7", "DarkHotel", "Molerat", "Okrum"],
        "spl_query": [
            'index=sysmon EventCode=1\n| search Image="*\\\\powershell.exe" OR Image="*\\\\cmd.exe"\n| search CommandLine="*Get-Clipboard*" OR CommandLine="*Shell.Application*" OR CommandLine="*RecentItems*"',
            'index=sysmon EventCode=10\n| search CallTrace="*GetLastInputInfo*" OR CallTrace="*GetCursorPos*"\n| stats count by Image, ProcessId',
            'index=registry\n| search registry_path="*UserAssist*" OR registry_path="*RecentDocs*" OR registry_path="*TypedPaths*"\n| stats count by registry_path, host'
        ],
        "hunt_steps": [
            "Review malware samples or binaries that include user interaction-gated payloads.",
            "Correlate execution timestamps with user session activity or lack thereof.",
            "Inspect calls to user interaction APIs in suspicious binaries.",
            "Monitor for low-interaction sandbox evasion patterns (e.g., GetForegroundWindow with inactivity)."
        ],
        "expected_outcomes": [
            "Identification of malware behavior that waits for real user input before executing.",
            "Detection of attempts to enumerate interaction artifacts like browser history or user files.",
            "Increased fidelity in sandbox or dynamic analysis environments through deception or emulation."
        ],
        "false_positive": "Some legitimate scripts or user-focused applications may query clipboard, window focus, or user activity logs. Cross-check timing, command context, and parent process lineage.",
        "clearing_steps": [
            "Remove malicious payloads or scripts: del C:\\Users\\Public\\usercheck.exe /Q",
            "Clear recently accessed files, clipboard logs, and browser cache from staging paths.",
            "Purge persistence from scheduled tasks or registry run keys conditioned on user input.",
            "Isolate machine for forensic review if evasion is suspected."
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1083", "example": "Listing desktop or documents folder for file count as a user presence check"},
            {"tactic": "Defense Evasion", "technique": "T1202", "example": "Waiting for user to double-click image or close document to detonate macro"}
        ],
        "watchlist": [
            "Use of GetLastInputInfo, GetCursorPos, or similar Windows APIs",
            "Processes querying browser profiles or clipboard without user action",
            "Files or macros that check for interaction artifacts before proceeding",
            "Low-interaction sandboxes with high malware termination rates"
        ],
        "enhancements": [
            "Deploy sandbox interaction simulators with random input delays.",
            "Correlate telemetry from multiple user interaction sources (clipboard, focus, window events).",
            "Develop detection signatures for known macro patterns gated by user actions."
        ],
        "summary": "User Activity Based Checks are a sandbox evasion method where adversaries assess host interactivity—mouse movements, browser history, open documents—to decide whether to proceed with payload execution or remain dormant.",
        "remediation": "Remove payloads relying on user interaction, purge staging paths and clipboard artifacts, terminate macros with gated logic, and simulate user interaction for dynamic analysis.",
        "improvements": "Improve sandbox realism with human activity emulation, enhance visibility into user-triggered behaviors, and build threat intel on interaction-dependent malware strains.",
        "mitre_version": "16.1"
    }
