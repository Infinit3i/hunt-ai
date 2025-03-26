def get_content():
    return {
        "id": "T1106",
        "url_id": "T1106",
        "title": "Native API",
        "description": "Adversaries may interact with the native OS application programming interface (API) to execute behaviors. Native APIs provide a controlled means of calling low-level OS services within the kernel, such as those involving hardware/devices, memory, and processes.",
        "tags": ["native api", "syscalls", "execution", "evasion", "low-level access"],
        "tactic": "execution",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Correlate suspicious DLL loads (e.g., ntdll.dll) with process lineage",
            "Use API call stack tracing to identify unauthorized system calls",
            "Monitor for uncommon sequences of native API usage"
        ],
        "data_sources": "Module, Process",
        "log_sources": [
            {"type": "Module", "source": "endpoint", "destination": ""},
            {"type": "Process", "source": "EDR", "destination": ""},
            {"type": "Process", "source": "sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Loaded DLLs", "location": "LoadedModules list in memory or via EDR", "identify": "ntdll.dll, kernel32.dll, advapi32.dll used suspiciously"},
            {"type": "Memory Dumps", "location": "Volatile memory or mini dumps", "identify": "Direct syscall or unhooking attempts"},
            {"type": "Windows Defender Logs", "location": "C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\", "identify": "Behavior-based detection alerts for process injection or API misuse"}
        ],
        "destination_artifacts": [
            {"type": "Process List", "location": "Live process telemetry", "identify": "Processes using syscalls without higher-level APIs"},
            {"type": "Registry Hives", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Services", "identify": "Malicious services registered to run API-heavy executables"},
            {"type": "Event Logs", "location": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "identify": "Process execution logs with low-level call indicators"}
        ],
        "detection_methods": [
            "Monitor for syscalls that bypass user-mode API hooks",
            "Alert on loading of system DLLs into non-standard processes",
            "Use behavioral analytics on sequence of API calls"
        ],
        "apt": [
            "APT41", "Turla", "Gamaredon", "Bumblebee", "Cobalt Kitty", "Silence", "REvil", "Lazarus Group", "WastedLocker", "Metador"
        ],
        "spl_query": [
            'index=sysmon EventCode=7 \n| search ImageLoaded=*ntdll.dll OR *advapi32.dll \n| stats count by Image, ImageLoaded',
            'index=sysmon EventCode=1 \n| search CommandLine="*syscall*" OR CommandLine="*NtCreate*" \n| stats count by Image, CommandLine',
            'index=wineventlog EventCode=4688 \n| where NewProcessName="*\\rundll32.exe" AND CommandLine="*ntdll*"'
        ],
        "hunt_steps": [
            "Identify processes loading system DLLs commonly used for native API calls",
            "Correlate unusual memory access patterns with direct syscall attempts",
            "Investigate dropped binaries or injected code using low-level APIs"
        ],
        "expected_outcomes": [
            "Detection of malware using syscalls to evade API hooks",
            "Uncovered use of unhooked or direct API invocation for stealth execution",
            "Correlated API abuse with process injection or obfuscation techniques"
        ],
        "false_positive": "Legitimate software frameworks (e.g., .NET apps) may invoke native APIs. Look for anomalies in process context, frequency, and surrounding behavior to reduce noise.",
        "clearing_steps": [
            "Quarantine binaries abusing native APIs",
            "Rehook or reinstall defensive tools if they were tampered with",
            "Review system DLL integrity with tools like sfc /scannow or sigcheck"
        ],
        "mitre_mapping": [
            {"tactic": "defense-evasion", "technique": "T1562.001", "example": "Unhooking EDR DLLs before syscall"},
            {"tactic": "execution", "technique": "T1059.003", "example": "PowerShell used to wrap syscall payload"},
            {"tactic": "privilege-escalation", "technique": "T1055.012", "example": "API-based process injection"}
        ],
        "watchlist": [
            "Processes loading ntdll.dll outside of known-good software",
            "Direct syscall patterns from scripts or .NET binaries",
            "Custom shellcode that does not rely on standard API libraries"
        ],
        "enhancements": [
            "Deploy syscall-level monitoring tools such as Sysmon or EDR extensions",
            "Correlate API activity with behavioral anomalies",
            "Deploy deception DLLs to detect unhooking or tampering"
        ],
        "summary": "Native API execution allows adversaries to leverage low-level OS functionality for stealthy execution, potentially bypassing security tools that rely on user-mode API monitoring.",
        "remediation": "Patch EDR bypasses, monitor critical DLL loading, and block known tools that enable syscall obfuscation.",
        "improvements": "Enhance visibility into native API usage through kernel-level monitoring or hardened endpoint protections.",
        "mitre_version": "16.1"
    }
