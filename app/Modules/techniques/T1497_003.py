def get_content():
    return {
        "id": "T1497.003",
        "url_id": "T1497/003",
        "title": "Virtualization/Sandbox Evasion: Time Based Evasion",
        "description": "Adversaries may employ various time-based methods to detect and avoid virtualization and analysis environments. This may include enumerating time-based properties, such as uptime or the system clock, as well as the use of timers or other triggers to avoid a virtual machine environment (VME) or sandbox, specifically those that are automated or only operate for a limited amount of time.",
        "tags": ["defense evasion", "discovery", "sandbox evasion", "sleep evasion", "api hammering", "time check", "delays", "native api"],
        "tactic": "Defense Evasion, Discovery",
        "protocol": "",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Look for execution delays that exceed expected timing profiles.",
            "Use memory forensics to inspect for embedded timers or sleep calls.",
            "Trace usage of native APIs or unnecessary ping loops that serve no logical purpose.",
            "Detect discrepancies in time sampling that compare pre/post sleep values."
        ],
        "data_sources": "Command, Process",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "Process", "source": "Process Creation", "destination": ""},
            {"type": "Process", "source": "OS API Execution", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Memory Dumps", "location": "Process space", "identify": "Presence of long sleep timers, loop counters, or delay logic"},
            {"type": "Event Logs", "location": "System Logs", "identify": "Initial process creation followed by delayed follow-up activity"},
            {"type": "Process List", "location": "Runtime view", "identify": "Execution of ping loops or timer-based evasion (e.g., ping 127.0.0.1 -n 50 > nul)"},
            {"type": "File Access Times (MACB)", "location": "Filesystem", "identify": "Gaps in file write timestamps matching evasion delays"},
            {"type": "Registry Hives", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Services", "identify": "Delayed scheduled execution using service keys"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Detect abnormal delays in process execution post-creation.",
            "Identify malware samples that use excessive ping loops or API hammering techniques.",
            "Monitor for native API use with no output or action taken.",
            "Check for time skew analysis logic where malware detects time acceleration (sandbox manipulation)."
        ],
        "apt": [
            "GuLoader", "QakBot", "DarkTortilla", "Tomiris", "Snip3", "Metador", "SUNBURST", "CactusPete", "Egregor", "Clop", "Team9", "NOBELIUM",
            "DRBControl", "Brute Ratel", "Lokibot", "Lazarus", "Bumblebee", "Agrius", "Ursnif", "Dukes", "EvilBunny", "Okrum", "Turla"
        ],
        "spl_query": [
            'index=os_logs EventCode=1\n| search CommandLine="*ping 127.0.0.1*" OR CommandLine="*timeout*" OR CommandLine="*sleep*"',
            'index=sysmon EventCode=10\n| search CallTrace="*Sleep*" OR CallTrace="*NtDelayExecution*" OR CallTrace="*WaitForSingleObject*"\n| stats count by Image, ProcessId',
            'index=process_logs\n| transaction ProcessName maxspan=5m\n| where duration > 300 AND process_name="unknown"'
        ],
        "hunt_steps": [
            "Identify binaries with delay functions in static analysis.",
            "Look for script chains that include sleep or ping-based delay logic.",
            "Trace post-delay behaviors and correlate with sandbox escape or payload execution.",
            "Analyze memory for native API calls or high-loop counters without logical purpose."
        ],
        "expected_outcomes": [
            "Detection of malware that delays execution to avoid sandbox analysis.",
            "Attribution of evasive behavior to specific techniques such as sleep obfuscation or API hammering.",
            "Improved sandbox environments through simulation of long execution times."
        ],
        "false_positive": "Administrative scripts may include timeout or ping delay for automation. Confirm behavior intent, execution context, and post-delay actions.",
        "clearing_steps": [
            "Terminate delay-based processes: taskkill /F /IM sleeper.exe",
            "Delete any scheduled task or service registry entries set to delay payload: schtasks /Delete /TN evasion /F",
            "Inspect scripting environments and remove staged delay payloads.",
            "Reboot system if API calls cause memory saturation or execution lockout."
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1053", "example": "Scheduled Tasks used to delay malware activation"},
            {"tactic": "Execution", "technique": "T1106", "example": "Use of native API hammering to consume time and overload analysis"},
            {"tactic": "Defense Evasion", "technique": "T1497", "example": "Overall sandbox evasion via time-based detection"}
        ],
        "watchlist": [
            "Execution of ping 127.0.0.1 with high -n values",
            "Unusual use of sleep or timeout commands in user sessions",
            "API usage patterns for known delay-related Win32 or Nt API functions",
            "Sample inactivity > 60 seconds followed by suspicious execution"
        ],
        "enhancements": [
            "Emulate long-duration sandbox execution or patch sleep APIs in test.",
            "Alert on combined sleep and systeminfo/registry recon patterns.",
            "Use decoy environment timers or clock drift simulations to catch time-checking logic."
        ],
        "summary": "Time Based Evasion allows adversaries to delay malicious activity until automated sandbox environments time out or are bypassed. This is done through sleeps, loops, or time sampling to trick analysis systems.",
        "remediation": "Terminate time-delaying binaries, remove staged persistence, analyze behavior for chained execution, and simulate time drift for future sandbox enhancement.",
        "improvements": "Deploy sleep patching and API hook monitoring, detect correlated time-check logic, and extend analysis runtime in sandbox environments.",
        "mitre_version": "16.1"
    }
