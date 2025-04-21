def get_content():
    return {
        "id": "T1574.008",
        "url_id": "T1574/008",
        "title": "Hijack Execution Flow: Path Interception by Search Order Hijacking",
        "description": "Adversaries may execute their own malicious payloads by exploiting the order in which Windows resolves executables when a full path is not specified. If an application launches another program or utility without an explicit path (e.g., calling `net` instead of `C:\\Windows\\System32\\net.exe`), Windows follows a standard search order to locate the executable.\n\nAn adversary can take advantage of this by dropping a malicious binary named identically to the expected utility (e.g., `net.exe`, `cmd.exe`) in a directory that is searched first—typically the directory of the calling application. Due to the default search order, Windows may resolve and execute the malicious version instead of the intended system utility.\n\nAdditionally, the use of `PATHEXT` allows prioritization of extensions (`.com` before `.exe`, etc.), which can be abused to hijack execution by naming files with extensions that take precedence. This technique is commonly used for persistence or privilege escalation when the hijacked process runs with elevated permissions.",
        "tags": ["Search Order Hijack", "Privilege Escalation", "Persistence", "Binary Injection", "Path Abuse"],
        "tactic": "Defense Evasion, Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Check for processes running executables from user-writable directories with names matching system utilities.",
            "Audit PATH environment variables and programmatic invocation of binaries.",
            "Avoid launching executables without specifying their full path in scripts or application code."
        ],
        "data_sources": "File: File Creation, File: File Modification, Process: Process Creation",
        "log_sources": [
            {"type": "File", "source": "Filesystem (e.g., Sysmon Event ID 11)", "destination": ""},
            {"type": "Process", "source": "Windows Event Logs or Sysmon (EID 1)", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "Application directory or user temp folders", "identify": "Executables matching common Windows utilities"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "Unexpected directories", "identify": "Process Image path pointing to non-system location"}
        ],
        "detection_methods": [
            "Monitor for new file creation where the filename matches that of known system binaries (e.g., `net.exe`, `ping.exe`).",
            "Alert on processes that spawn from non-standard paths or unusual locations with system utility names.",
            "Check for shadow copies of system utilities in locations like `%APPDATA%`, `%TEMP%`, or the application's working directory.",
            "Analyze process ancestry and PATH environment during execution for suspicious overrides."
        ],
        "apt": [],
        "spl_query": [
            "index=sysmon EventCode=11 TargetFilename IN (\"*\\\\net.exe\", \"*\\\\cmd.exe\", \"*\\\\python.exe\")\n| search NOT TargetFilename=\"C:\\\\Windows\\\\System32\\\\*\"\n| stats count by TargetFilename, Image, User"
        ],
        "hunt_steps": [
            "Enumerate applications/scripts that invoke executables without full paths.",
            "Check directories for suspicious binaries mimicking legitimate Windows utilities.",
            "Inspect PATH and PATHEXT environment variables for custom additions or override behavior."
        ],
        "expected_outcomes": [
            "Detection of unauthorized binaries shadowing Windows utilities.",
            "Identification of misconfigured programs or scripts using relative or no path references.",
            "Compromised execution flow enabling adversarial persistence or escalation."
        ],
        "false_positive": "System administrators may create legitimate wrappers or aliases with similar names during development or testing. Validate against internal change control records.",
        "clearing_steps": [
            "Remove the malicious binaries from user-writable or application directories.",
            "Reconfigure vulnerable applications to use full paths when calling other programs.",
            "Audit and restore proper PATH environment configurations."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1574.008", "example": "Creating fake net.exe to persist in custom app directories"},
            {"tactic": "Privilege Escalation", "technique": "T1574.008", "example": "Hijacking elevated process search to run malicious binary"}
        ],
        "watchlist": [
            "Executables created in the working directory of custom apps",
            "Processes running `cmd.exe`, `net.exe`, etc. from non-standard paths",
            "PATHEXT manipulation or registry changes involving execution behavior"
        ],
        "enhancements": [
            "Implement application whitelisting (e.g., AppLocker or WDAC)",
            "Use Group Policy to block execution from temp/user directories",
            "Enforce strict developer practices to always use fully qualified paths"
        ],
        "summary": "Path Interception by Search Order Hijacking exploits the implicit resolution order of executables in Windows when full paths are not provided. Adversaries can inject malicious binaries in directories that get searched first, resulting in the hijacking of execution flow and potentially leading to persistence or privilege escalation.",
        "remediation": "Educate developers to use explicit paths. Harden directory permissions. Deploy endpoint monitoring to alert on execution anomalies.",
        "improvements": "Add static and runtime checks during software builds for unsafe process invocation patterns. Integrate execution context validation in SOAR pipelines.",
        "mitre_version": "16.1"
    }
