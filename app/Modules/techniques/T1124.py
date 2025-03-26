def get_content():
    return {
        "id": "T1124",
        "url_id": "T1124",
        "title": "System Time Discovery",
        "description": "An adversary may gather the system time and/or time zone settings from a local or remote system.",
        "tags": ["time discovery", "timestamp", "recon", "timezone", "sandbox evasion"],
        "tactic": "discovery",
        "protocol": "",
        "os": "Linux, Network, Windows, macOS",
        "tips": [
            "Correlate timestamp checks with follow-on scheduled or delayed execution",
            "Alert on excessive use of w32tm, systemsetup, or uptime queries",
            "Investigate time-based logic in malware samples or scripts"
        ],
        "data_sources": "Command, Process",
        "log_sources": [
            {"type": "Command", "source": "endpoint", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""},
            {"type": "Process", "source": "EDR", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Command History", "location": "~/.bash_history or PowerShell logs", "identify": "Usage of net time, w32tm /tz, uptime, date"},
            {"type": "Event Logs", "location": "Security.evtx", "identify": "Execution of time discovery tools"},
            {"type": "Process List", "location": "EDR or Sysmon telemetry", "identify": "Processes running clock/time zone queries"}
        ],
        "destination_artifacts": [
            {"type": "Windows Defender Logs", "location": "C:\\ProgramData\\Microsoft\\Windows Defender\\", "identify": "Suspicious commands tied to time gathering"},
            {"type": "Registry Hives", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation", "identify": "System time zone details"},
            {"type": "Memory Dumps", "location": "Live response snapshots", "identify": "Functions like GetTickCount or time() in execution chain"}
        ],
        "detection_methods": [
            "Detect execution of net time, systemsetup, w32tm, GetTickCount, or uptime",
            "Flag repeated or automated queries to remote systems for time information",
            "Correlate system time checks with anti-analysis or sandbox evasion logic"
        ],
        "apt": [
            "APT41", "BRONZE BUTLER", "DarkWatchman", "Gamaredon", "Zebrocy", "OilRig", "ComRAT", "Metamorfo", "Higaisa", "InvisiMole"
        ],
        "spl_query": [
            'index=wineventlog OR index=sysmon \n| search CommandLine="*net time*" OR CommandLine="*w32tm*" OR CommandLine="*uptime*" OR CommandLine="*date*" \n| stats count by Image, CommandLine, User',
            'index=sysmon EventCode=1 \n| search CommandLine="*systemsetup -gettimezone*" OR CommandLine="*GetTickCount*" \n| stats count by Computer, Image',
            'index=process OR index=powershell \n| search ScriptBlockText="*time()*" OR ScriptBlockText="*sleep until*" \n| stats count by User, ScriptBlockText'
        ],
        "hunt_steps": [
            "Identify PowerShell or cmd.exe processes invoking time discovery commands",
            "Review remote system queries that include net time or show clock",
            "Analyze persistence scripts or malware for execution delays or time bombs"
        ],
        "expected_outcomes": [
            "Detection of scripts and tools performing time discovery pre/post compromise",
            "Recognition of sandbox evasion or time-based execution delay behaviors",
            "Detection of adversary attempting to determine target locality or uptime"
        ],
        "false_positive": "Legitimate automation, inventory, and troubleshooting tools may query system time. Context such as command origin, frequency, and user privilege level is key.",
        "clearing_steps": [
            "Remove scripts using system time to delay or gate execution",
            "Re-image or monitor endpoints exhibiting anomalous time discovery usage",
            "Investigate broader toolkits (e.g., RATs) where time checks are part of logic"
        ],
        "mitre_mapping": [
            {"tactic": "evasion", "technique": "T1497.001", "example": "Malware delays execution if system time doesn't match expected locale"},
            {"tactic": "execution", "technique": "T1053", "example": "System time used to schedule future payload run"},
            {"tactic": "collection", "technique": "T1614.001", "example": "Time zone discovery used to determine physical location of target"}
        ],
        "watchlist": [
            "Use of time-based conditional logic in macros, scripts, or payloads",
            "Remote system queries that include net time \\hostname",
            "System time access paired with registry enumeration"
        ],
        "enhancements": [
            "Enable command line auditing and process command logging",
            "Track DLL usage for time-related APIs in userland and kernel",
            "Deploy sandbox detection logic that includes rapid time checks"
        ],
        "summary": "System Time Discovery is often used by adversaries to assess victim environment context, evade sandboxes, or synchronize malicious actions. It can also aid in targeting based on location or device uptime.",
        "remediation": "Limit use of time-based scripting or commands. Harden auditing to track system time access and correlate with lateral movement or evasion activity.",
        "improvements": "Develop heuristics for abnormal frequency or patterns of time discovery across hosts. Integrate alerts with deception-based time response mechanisms.",
        "mitre_version": "16.1"
    }
