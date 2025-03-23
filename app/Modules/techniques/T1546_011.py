def get_content():
    return {
        "id": "T1546.011",
        "url_id": "T1546/011",
        "title": "Event Triggered Execution: Application Shimming",
        "description": "Adversaries may use application shims to achieve persistence or elevate privileges by hooking into the execution flow of applications via malicious shim databases.",
        "tags": ["Application Shimming", "Persistence", "Privilege Escalation", "sdbinst", "Windows Compatibility"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Audit installed shim databases for unexpected or unsigned entries.",
            "Monitor usage of `sdbinst.exe` to install or modify shim databases.",
            "Look for registry changes under appcompatflags."
        ],
        "data_sources": "Command: Command Execution, File: File Modification, Module: Module Load, Process: Process Creation, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "Command", "source": "CLI", "destination": "sdbinst.exe usage"},
            {"type": "Windows Registry", "source": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags", "destination": "Custom or installed SDBs"},
            {"type": "File", "source": "%WINDIR%\\AppPatch\\Custom", "destination": "Shim DLL injection paths"},
            {"type": "Process", "source": "", "destination": "Processes injected with malicious shim DLLs"}
        ],
        "source_artifacts": [
            {"type": "Executable", "location": "%SystemRoot%\\System32\\sdbinst.exe", "identify": "Used to install custom shim database"},
            {"type": "Registry Key", "location": "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom", "identify": "Lists custom SDB entries"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "%WINDIR%\\AppPatch\\Custom\\*.sdb", "identify": "Custom shim DBs used for redirection or injection"},
            {"type": "Process", "location": "Any application with shim redirection", "identify": "Redirected or injected via shims"}
        ],
        "detection_methods": [
            "Monitor and alert on `sdbinst.exe` execution with new SDB files",
            "Detect unexpected changes in AppCompatFlags registry keys",
            "Use forensic tools like ShimScanner or ShimCacheMem",
            "Review new file writes in `%WINDIR%\\AppPatch\\Custom`"
        ],
        "apt": ["FIN7", "TA505", "Mofang"],
        "spl_query": [
            'index=main sourcetype=WinRegistry Registry.key="*AppCompatFlags*Custom*" \n| stats count by Registry.path, Registry.value, User',
            'index=main sourcetype=ProcessCreation Image="*sdbinst.exe*" \n| table _time, Image, CommandLine, ParentProcessName'
        ],
        "hunt_steps": [
            "Search for recent executions of sdbinst.exe",
            "Check file system for unauthorized .sdb files",
            "Dump and examine shim DB contents using tools like `shimdbc`",
            "Cross-reference process behaviors tied to shims"
        ],
        "expected_outcomes": [
            "Detection of malicious shim database installations",
            "Privilege escalation via DLL injection from shimmed apps",
            "Persistence via shim redirection surviving reboots"
        ],
        "false_positive": "Legitimate developers may use shims for backward compatibility. Validate SDB contents and authorship before alerting.",
        "clearing_steps": [
            "Remove the malicious SDB via `sdbinst -u <path>`",
            "Delete or quarantine the corresponding .sdb file",
            "Purge related entries from the AppCompatFlags registry",
            "Reboot to clear shim cache from memory"
        ],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1548.002", "example": "UAC bypass using shims like RedirectEXE"},
            {"tactic": "Defense Evasion", "technique": "T1055", "example": "DLL injection via shim configuration"}
        ],
        "watchlist": [
            "Shim-related file drops in `AppPatch\\Custom`",
            "Unexpected registry keys in AppCompatFlags\\Custom",
            "Command-line activity invoking sdbinst.exe"
        ],
        "enhancements": [
            "Harden endpoints to restrict admin rights required for shim installation",
            "Log and alert on all use of `sdbinst.exe`",
            "Perform regular integrity checks on `AppPatch` directory"
        ],
        "summary": "Application shimming is a Windows feature that enables backward compatibility. Adversaries abuse it to inject DLLs or redirect execution flow via crafted shim databases, often for persistence or privilege escalation.",
        "remediation": "Uninstall unauthorized shims, revoke related privileges, review associated application integrity, and implement allow-listing to prevent rogue injections.",
        "improvements": "Enforce strict application control policies. Monitor registry, process, and file-level changes related to shim deployment. Train IR teams to spot shim abuse.",
        "mitre_version": "16.1"
    }
