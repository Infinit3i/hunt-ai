def get_content():
    return {
        "id": "T1546.010",
        "url_id": "T1546/010",
        "title": "Event Triggered Execution: AppInit DLLs",
        "description": "Adversaries may use AppInit DLLs to execute code in the context of user-mode processes by loading malicious DLLs through the AppInit_DLLs registry key.",
        "tags": ["AppInitDLLs", "DLL injection", "persistence", "privilege escalation", "registry persistence"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Check AppInit_DLLs registry values for unknown or unsigned DLLs.",
            "Use secure boot to disable AppInit functionality on Windows 8 and newer systems.",
            "Correlate DLL loads from user32.dll with registry-based injection."
        ],
        "data_sources": "Command: Command Execution, Module: Module Load, Process: OS API Execution, Process: Process Creation, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "Windows Registry", "source": "HKLM\\...\\AppInit_DLLs", "destination": "DLL path values used for injection"},
            {"type": "Module", "source": "", "destination": "DLLs loaded into user32.dll context"},
            {"type": "Command", "source": "CLI or script", "destination": "Registry modification utilities"},
            {"type": "Process", "source": "", "destination": "Processes injecting malicious DLLs via AppInit"}
        ],
        "source_artifacts": [
            {"type": "Registry Key", "location": "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs", "identify": "Points to injected DLL"},
            {"type": "File", "location": "C:\\Windows\\System32\\malicious.dll", "identify": "DLL loaded persistently"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "Processes using user32.dll", "identify": "Abnormal injected DLLs"},
            {"type": "Network", "location": "Outbound connections from injected process", "identify": "Potential C2 behavior"}
        ],
        "detection_methods": [
            "Monitor AppInit_DLLs registry keys for suspicious modifications",
            "Analyze DLLs loaded by user32.dll across multiple processes",
            "Use Autoruns to identify persistent DLL injection",
            "Monitor RegSetValueEx and related API calls modifying AppInit keys"
        ],
        "apt": ["APT39", "Ramsay", "T9000"],
        "spl_query": [
            'index=main Registry.path="*AppInit_DLLs*" \n| stats count by Registry.path, Registry.value, Image, User'
        ],
        "hunt_steps": [
            "Dump and analyze AppInit_DLLs registry values",
            "Hash and inspect DLLs referenced in registry",
            "Trace process behavior resulting from AppInit injection",
            "Correlate injected DLLs to known malware or unsigned binaries"
        ],
        "expected_outcomes": [
            "Malicious DLLs loading into multiple processes",
            "Persistence across user sessions without creating services",
            "Privilege escalation through AppInit DLL code execution"
        ],
        "false_positive": "Legitimate software may rarely use AppInit_DLLs. Any use should be reviewed and whitelisted explicitly.",
        "clearing_steps": [
            "Delete or clean AppInit_DLLs registry values",
            "Remove the malicious DLL from disk",
            "Reboot the system to stop further DLL injection",
            "Re-enable secure boot where possible to disable AppInit usage"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1112", "example": "Registry modification for stealth persistence"},
            {"tactic": "Privilege Escalation", "technique": "T1055", "example": "Process injection using DLL via AppInit"}
        ],
        "watchlist": [
            "Changes to AppInit_DLLs in registry",
            "Unexpected DLLs in user32.dll-injected processes",
            "Reg.exe or PowerShell modifying registry keys under NT\\CurrentVersion\\Windows"
        ],
        "enhancements": [
            "Apply Windows security baselines that disable AppInit_DLLs",
            "Use secure boot on supported systems",
            "Enable process auditing to catch unusual DLL loads"
        ],
        "summary": "AppInit_DLLs is a legacy Windows mechanism for injecting DLLs into user-mode processes via user32.dll. Adversaries exploit this to achieve persistence or privilege escalation.",
        "remediation": "Clear AppInit DLL paths from registry, delete rogue DLLs, enforce secure boot, and monitor affected systems.",
        "improvements": "Limit registry write access, disable unnecessary registry persistence mechanisms, and track DLL injection at the EDR level.",
        "mitre_version": "16.1"
    }
