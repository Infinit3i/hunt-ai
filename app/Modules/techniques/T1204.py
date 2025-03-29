def get_content():
    return {
        "id": "T1204",
        "url_id": "T1204",
        "title": "User Execution",
        "description": "An adversary may rely upon specific actions by a user in order to gain execution.",
        "tags": ["Execution", "Phishing", "Social Engineering", "Macro Malware", "User-Driven"],
        "tactic": "Execution",
        "protocol": "HTTP/HTTPS, SMB, Email (SMTP, IMAP, POP3)",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Monitor process execution for script interpreters like wscript.exe, powershell.exe, and mshta.exe.",
            "Analyze execution of files with suspicious extensions (.docm, .lnk, .js).",
            "Correlate email and proxy logs with endpoint execution telemetry."
        ],
        "data_sources": "Application Log, Command, File, Image, Instance, Network Traffic, Process",
        "log_sources": [
            {"type": "Process", "source": "Sysmon Event ID 1", "destination": ""},
            {"type": "Command", "source": "Windows Event ID 4688", "destination": ""},
            {"type": "Application Log", "source": "Microsoft Office", "destination": ""},
            {"type": "File", "source": "User Downloads", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Email Attachments", "location": "User inbox", "identify": "Macro-enabled documents or executables"},
            {"type": "Web Downloads", "location": "%UserProfile%\\Downloads", "identify": "Files with extensions like .exe, .vbs, .js"}
        ],
        "destination_artifacts": [
            {"type": "Registry Keys", "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "identify": "Persistence setup by user-executed malware"},
            {"type": "Process Execution", "location": "Memory", "identify": "LOLBin or script interpreter processes triggered by users"}
        ],
        "detection_methods": [
            "Behavioral analysis of macro or script-initiated child processes",
            "Monitoring file execution in user-space directories",
            "Detection of suspicious file extensions associated with phishing"
        ],
        "apt": [
            "Scattered Spider", "MSTIC DEV-0537", "Raspberry Robin", "Pikabot"
        ],
        "spl_query": [
            "index=windows EventCode=4688 (Image=\"*wscript.exe\" OR Image=\"*powershell.exe\" OR Image=\"*mshta.exe\")\n| stats count by Image, CommandLine, ParentProcessName",
            "index=email subject=* OR attachment=* (attachment_ext=\"docm\" OR attachment_ext=\"vbs\" OR attachment_ext=\"lnk\")\n| table sender, subject, attachment_name"
        ],
        "hunt_steps": [
            "Hunt for scripting interpreters launched from Office or PDF readers",
            "Pivot on file hashes from downloaded email attachments",
            "Trace registry or scheduled task persistence from executed payloads"
        ],
        "expected_outcomes": [
            "Detection of user-triggered execution from phishing vectors",
            "Awareness of social engineering techniques targeting users"
        ],
        "false_positive": "Internal tools or scripts may trigger false positives. Validate source, command line, and user intent.",
        "clearing_steps": [
            "taskkill /F /IM powershell.exe",
            "Delete suspicious files from Downloads, AppData, and Temp directories",
            "Remove persistence entries in HKCU Run keys",
            "Flush DNS and browser history"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1566.001", "example": "Spearphishing attachment leads to user execution"},
            {"tactic": "Execution", "technique": "T1059", "example": "User opens a macro document which spawns PowerShell"}
        ],
        "watchlist": [
            "Execution of Office macros, scripting engines, or compressed files",
            "LOLBin invocation from user directories or after file downloads"
        ],
        "enhancements": [
            "Implement ASR rules to block Office macro execution and scripting abuse",
            "Force Protected View for all Office files from the internet",
            "Use secure email gateways and sandboxing for attachment analysis"
        ],
        "summary": "User Execution involves adversaries relying on users to execute malicious code, often through phishing, social engineering, or drive-by downloads. It’s a critical step for many attacks and often bypasses technical defenses.",
        "remediation": "Deploy script-blocking policies, educate users on phishing, and ensure endpoint visibility into user-driven file execution.",
        "improvements": "Strengthen phishing detection, enforce attachment scanning, and correlate user interaction with execution events.",
        "mitre_version": "16.1"
    }
