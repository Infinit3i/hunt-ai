def get_content():
    return {
        "id": "T1574.009",
        "url_id": "T1574/009",
        "title": "Hijack Execution Flow: Path Interception by Unquoted Path",
        "description": "Adversaries may exploit unquoted service or shortcut paths in Windows that include spaces and are not wrapped in quotes. In such cases, Windows attempts to resolve the executable by splitting the path and checking each sub-path for an executable file. If an adversary drops a malicious executable at one of these sub-paths (e.g., `C:\\Program.exe` instead of `C:\\Program Files\\App\\app.exe`), it may get executed instead of the intended binary.\n\nThis path hijacking technique is especially dangerous when the targeted path belongs to a service or executable that runs with elevated privileges. If a service configured to run as SYSTEM uses an unquoted path and a malicious executable is resolved first, it could result in privilege escalation. Similarly, regular invocation of such paths can be abused for persistence.",
        "tags": ["Path Hijack", "Privilege Escalation", "Persistence", "Unquoted Service Path", "Shortcut Exploit", "File Injection"],
        "tactic": "Defense Evasion, Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Use tools like `sc qc` or `PowerShell` to enumerate unquoted service paths.",
            "Look for file creation attempts in top-level directories like `C:\\`, especially with executable names.",
            "Avoid creating services with unquoted paths containing spaces."
        ],
        "data_sources": "File: File Creation, File: File Modification, Process: Process Creation",
        "log_sources": [
            {"type": "File", "source": "Filesystem monitoring (e.g., Sysmon EID 11)", "destination": ""},
            {"type": "Process", "source": "Sysmon or Windows Event Logs", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "C:\\", "identify": "Suspicious .exe like C:\\Program.exe"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "Service host or invoked executable", "identify": "Process started from unintended path"}
        ],
        "detection_methods": [
            "Monitor for process executions from unexpected paths like `C:\\Program.exe` or `C:\\Users\\Public\\update.exe`.",
            "Use tools such as Autoruns and Process Monitor to flag unquoted service paths.",
            "Alert on creation of executables in directories that are normally read-only or system-owned.",
            "Flag unsigned executables in ambiguous paths or with suspicious names."
        ],
        "apt": [],
        "spl_query": [
            "index=sysmon EventCode=11 TargetFilename=\"C:\\\\*.exe\"\n| search TargetFilename=*program.exe OR *update.exe\n| stats count by TargetFilename, Image, User"
        ],
        "hunt_steps": [
            "Enumerate services with unquoted paths using: `wmic service get name,displayname,pathname,startmode | findstr /i /v \"\"`",
            "Search for `.exe` files at the root of the filesystem and top-level directories.",
            "Check Windows Defender or antivirus logs for unexpected process launches from high-risk directories."
        ],
        "expected_outcomes": [
            "Discovery of unquoted service paths with exploitable spaces",
            "Evidence of malicious executables injected into vulnerable paths",
            "Detection of privilege escalation attempts via path hijacking"
        ],
        "false_positive": "Software installers or update agents may create temporary binaries in top-level directories during legitimate operations. Context such as timing, frequency, and process lineage should be evaluated.",
        "clearing_steps": [
            "Quote service paths in the Registry under `HKLM\\SYSTEM\\CurrentControlSet\\Services\\<ServiceName>`",
            "Remove any malicious executables created in root or common directories",
            "Apply security ACLs to restrict write access to system directories"
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1574.009", "example": "Dropping malicious file in `C:\\` to hijack service path"},
            {"tactic": "Privilege Escalation", "technique": "T1574.009", "example": "Hijacking SYSTEM service by exploiting unquoted path"}
        ],
        "watchlist": [
            "Creation of .exe files in `C:\\`, `C:\\Users\\Public`, or similar paths",
            "Process executions originating from ambiguous or partial paths",
            "Service executions referencing paths without surrounding quotes"
        ],
        "enhancements": [
            "Configure GPO to enforce strict service creation and audit policies",
            "Run regular scans using tools like `AccessChk`, `Autoruns`, or `PowerUp` to identify misconfigurations",
            "Use application whitelisting (e.g., AppLocker, WDAC) to restrict unauthorized binaries"
        ],
        "summary": "This technique exploits a long-standing flaw in how Windows resolves unquoted paths with spaces. By injecting malicious executables into paths like `C:\\Program.exe`, adversaries can hijack legitimate service or application execution flows.",
        "remediation": "Quote all service paths in the Registry. Remove any unauthorized executables from vulnerable paths. Harden folder permissions to block file drops.",
        "improvements": "Integrate unquoted path analysis into CI/CD and deployment workflows to prevent service misconfiguration. Leverage software restriction policies or endpoint monitoring solutions.",
        "mitre_version": "16.1"
    }
