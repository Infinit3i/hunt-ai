def get_content():
    return {
        "id": "T1620",
        "url_id": "T1620",
        "title": "Reflective Code Loading",
        "description": "Adversaries may use reflective code loading to execute malicious payloads directly in memory, avoiding creation of artifacts on disk and evading traditional process-based detection. This involves dynamically loading compiled code (e.g., shellcode or binary blobs) into a process's own memory space using APIs like `Assembly.Load()` in PowerShell or `CreateThread()` and `execve()` in native platforms. This is similar to Process Injection but avoids targeting a remote process, operating instead within the same memory context.",
        "tags": ["fileless", "in-memory execution", "shellcode", "PowerShell", "Assembly.Load", "CreateThread", "defense evasion", "native API", "dotnet abuse"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Use AMSI/ETW tracing to detect abnormal .NET loading behavior.",
            "Alert on unusual use of CLR DLLs in suspicious processes like notepad.exe.",
            "Inspect memory for injected shellcode without associated file artifacts."
        ],
        "data_sources": "Module: Module Load, Process: OS API Execution, Script: Script Execution",
        "log_sources": [
            {"type": "Module", "source": "Windows Defender, ETW, AMSI", "destination": ""},
            {"type": "Process", "source": "Sysmon, EDR agent logs", "destination": ""},
            {"type": "Script", "source": "PowerShell logs, AMSI traces", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Memory Allocation", "location": "Local process memory", "identify": "Unbacked memory segments with executable code"},
            {"type": "API Calls", "location": "Process logs", "identify": "CreateThread, VirtualAlloc, execve without child processes"},
            {"type": "Module Loads", "location": "System32/CLR", "identify": "Unexpected .NET runtime DLLs in user processes"}
        ],
        "destination_artifacts": [
            {"type": "Memory-resident payload", "location": "In-process memory", "identify": "Obfuscated or encoded payload loaded via script"},
            {"type": "Stealth Execution", "location": "Running process", "identify": "Lack of traditional file-backed execution"}
        ],
        "detection_methods": [
            "Flag suspicious CLR (.NET) DLL loads in non-standard processes.",
            "Monitor for memory allocations marked executable without file I/O.",
            "Use behavioral detection on PowerShell commands using Assembly.Load or similar APIs."
        ],
        "apt": [
            "FIN8: Used reflective code loading in their malware framework.",
            "APT43: Leveraged reflective loaders to deploy encrypted payloads filelessly.",
            "Turla: Known to use memory-only backdoors that reflectively load modules."
        ],
        "spl_query": "index=sysmon sourcetype=Sysmon:ProcessCreate \n| search Image=*notepad.exe* AND (LoadedModule=*clr.dll* OR LoadedModule=*mscoree.dll*) \n| stats count by Image, LoadedModule, ParentProcessName",
        "spl_rule": "https://research.splunk.com/detections/tactics/defense-evasion/",
        "elastic_rule": "https://grep.app/search?f.repo=elastic%2Fdetection-rules&q=T1620",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1620",
        "hunt_steps": [
            "Search for processes loading .NET runtime modules (clr.dll) unexpectedly.",
            "Investigate memory regions in suspicious processes using Volatility or Rekall.",
            "Trace usage of Assembly.Load, CreateThread, or VirtualAlloc via ETW logs.",
            "Search for anonymous in-memory PE or ELF artifacts.",
            "Hunt for processes making outbound connections immediately after unusual memory activity."
        ],
        "expected_outcomes": [
            "Detection of in-memory payloads executed via reflective techniques.",
            "Uncovered evasive malware avoiding traditional file-based forensics.",
            "Improved behavioral signatures for API-based evasion techniques."
        ],
        "false_positive": "Legitimate .NET or script-based applications may use Assembly.Load(). Baseline environment usage to reduce noise.",
        "clearing_steps": [
            "Terminate affected process and dump memory for analysis.",
            "Blacklist or block identified script or tool responsible for loading payload.",
            "Audit EDR configuration for memory-based alerting capabilities."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1620 (Reflective Code Loading)", "example": "Adversaries using PowerShell Assembly.Load() to reflectively execute C2 shellcode."}
        ],
        "watchlist": [
            "Track usage of CreateThread, VirtualAllocEx, and Assembly.Load.",
            "Monitor for DLLs like clr.dll loaded in uncommon parent processes.",
            "Watch for fileless PowerShell execution behaviors."
        ],
        "enhancements": [
            "Implement in-memory anomaly detection through EDR or AMSI hooks.",
            "Enrich telemetry with script execution tracing and .NET module loads.",
            "Develop YARA rules for reflective payload artifacts in memory."
        ],
        "summary": "Reflective Code Loading allows threat actors to execute payloads from memory without touching disk, evading AV and traditional process injection detections. This technique operates within the current process's memory space and can involve shellcode, PowerShell, or native API abuse.",
        "remediation": "Kill suspicious processes, quarantine affected systems, and enrich threat detection with memory telemetry and ETW events.",
        "improvements": "Enhance behavioral detection, improve YARA memory scanning coverage, and expand endpoint visibility into script and API-based behaviors.",
        "mitre_version": "16.1"
    }
