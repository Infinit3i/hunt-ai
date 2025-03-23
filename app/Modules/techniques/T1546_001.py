def get_content():
    return {
        "id": "T1546.001",
        "url_id": "T1546/001",
        "title": "Event Triggered Execution: Change Default File Association",
        "description": "Adversaries may establish persistence by modifying file associations so that opening certain file types executes malicious commands instead of their default applications.",
        "tags": ["Persistence", "Registry Modification", "File Association", "Execution Hijacking"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor registry keys related to file associations, especially for suspicious commands.",
            "Correlate unknown file extensions triggering command-line tools or scripts.",
            "Regularly audit file extension handlers for unusual modifications."
        ],
        "data_sources": "Command: Command Execution, Process: Process Creation, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "Windows Registry", "source": "HKEY_CLASSES_ROOT", "destination": "Handler command keys"},
            {"type": "Windows Registry", "source": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts", "destination": "User-specific overrides"},
            {"type": "Command", "source": "CLI or script", "destination": "Changes via assoc/ftype utilities"},
            {"type": "Process", "source": "", "destination": "Unusual command execution from document/file opening"}
        ],
        "source_artifacts": [
            {"type": "Registry", "location": "HKEY_CLASSES_ROOT\\.<extension>", "identify": "Extension handler mapping"},
            {"type": "Registry", "location": "HKEY_CLASSES_ROOT\\[handler]\\shell\\open\\command", "identify": "Command to execute file type"}
        ],
        "destination_artifacts": [
            {"type": "Command", "location": "CLI", "identify": "assoc or ftype used to change associations"},
            {"type": "Process", "location": "Child of file open action", "identify": "Unexpected command-line process spawned"}
        ],
        "detection_methods": [
            "Monitor registry changes in file association keys under HKEY_CLASSES_ROOT and HKEY_CURRENT_USER",
            "Detect use of `assoc` or `ftype` in CLI by non-admin users or scripting engines",
            "Review processes launched as children of document viewers (e.g., notepad.exe launching cmd.exe)"
        ],
        "apt": ["Kimsuky"],
        "spl_query": [
            'index=main sourcetype=WinRegistry Registry.key="*\\shell\\open\\command" \n| stats count by Registry.path, Registry.value',
            'index=main sourcetype=ProcessCreation ParentProcessName="notepad.exe" \n| search Image="*cmd.exe*"'
        ],
        "hunt_steps": [
            "Search for registry modifications in file handler paths",
            "Hunt for usage of `assoc` or `ftype` in script logs or PowerShell history",
            "Look for abnormal child process chains involving document applications"
        ],
        "expected_outcomes": [
            "Persistence mechanism executes adversary-controlled process on file open",
            "Hijacked default file extensions trigger malware silently"
        ],
        "false_positive": "Some software may legitimately modify file associations for custom extensions or shell enhancements. Validate against known software installers.",
        "clearing_steps": [
            "Restore original file association registry values",
            "Use `assoc` and `ftype` to reset handlers to default",
            "Remove or quarantine associated malicious executables"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1112", "example": "Registry keys altered to mislead analysts or avoid AV"},
            {"tactic": "Execution", "technique": "T1204.002", "example": "User opens file with hijacked association triggering malware"}
        ],
        "watchlist": [
            "Changes to `.lnk`, `.txt`, `.docx` and `.exe` handlers",
            "Command-line execution involving `assoc`, `ftype`, or `reg add` for handler keys"
        ],
        "enhancements": [
            "Use GPO to enforce default application associations",
            "Implement file integrity monitoring on critical registry paths"
        ],
        "summary": "Changing default file associations is a persistence and execution technique where adversaries hijack the handler used when files are opened to run their malicious code instead.",
        "remediation": "Reset file handlers using `assoc` and `ftype`, or via Group Policy. Audit registry keys under HKCR and HKCU for unauthorized command paths.",
        "improvements": "Deploy endpoint detection rules for registry tampering in shell command handlers and alert on suspicious file-to-process chains.",
        "mitre_version": "16.1"
    }
