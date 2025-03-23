def get_content():
    return {
        "id": "T1546.012",
        "url_id": "T1546/012",
        "title": "Event Triggered Execution: Image File Execution Options Injection",
        "description": "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by Image File Execution Options (IFEO) debuggers.",
        "tags": ["persistence", "privilege escalation", "windows", "registry", "debugger", "IFEO", "silent process exit"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor usage of GFlags and registry modifications for debugging behavior.",
            "Alert on processes being spawned with debugging flags or abnormal parent-child process trees."
        ],
        "data_sources": "Command, Process, Windows Registry",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor for abnormal usage of GFlags.",
            "Watch for process creation using DEBUG_PROCESS flags.",
            "Track registry keys related to Image File Execution Options and SilentProcessExit."
        ],
        "apt": [],
        "spl_query": [
            "index=sysmon EventCode=1 Image=*cmd.exe* ParentImage=*utilman.exe*",
            "index=windows_registry registry_path=\"*\\Image File Execution Options\\*\" registry_value_name=Debugger"
        ],
        "hunt_steps": [
            "Search for IFEO registry key modifications.",
            "Look for processes executed under debugger parent processes.",
            "Inspect SilentProcessExit registry values for unknown binaries."
        ],
        "expected_outcomes": [
            "Detection of debugger usage linked to suspicious binaries.",
            "Identification of persistence via modified IFEO values."
        ],
        "false_positive": "Legitimate debugging or troubleshooting tools may modify IFEO keys. Validate context and binary locations.",
        "clearing_steps": [
            "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<target_exe>\" /v Debugger /f",
            "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\<target_exe>\" /f"
        ],
        "mitre_mapping": [
            {
                "tactic": "Defense Evasion",
                "technique": "T1562 - Impair Defenses",
                "example": "IFEO debugger entry disables antivirus executable."
            }
        ],
        "watchlist": [
            "Monitor processes launched with debugging enabled.",
            "Track registry paths: Image File Execution Options and SilentProcessExit."
        ],
        "enhancements": [
            "Enable registry auditing for the IFEO and SilentProcessExit keys.",
            "Alert on use of uncommon debuggers or tools spawning unexpected binaries."
        ],
        "summary": "This technique abuses Windows' IFEO mechanism to attach debuggers or monitor programs to other processes, often leading to privilege escalation or persistence.",
        "remediation": "Remove any malicious debugger entries from the registry and disable silent process exit features not explicitly required.",
        "improvements": "Enhance behavioral analytics for debugger-based persistence, and maintain whitelist of legitimate debugging tools.",
        "mitre_version": "16.1"
    }
