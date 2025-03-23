def get_content():
    return {
        "id": "T1027.007",
        "url_id": "T1027/007",
        "title": "Obfuscated Files or Information: Dynamic API Resolution",
        "description": "Adversaries may use dynamic API resolution to obfuscate function calls, concealing malicious behavior until runtime.",
        "tags": ["dynamic api resolution", "obfuscation", "GetProcAddress", "LoadLibrary", "runtime loading"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Detect usage of API hashing functions and calls to GetProcAddress or LoadLibrary.",
            "Monitor memory sections marked as executable that don't originate from files.",
            "Look for obfuscated or encrypted strings that are decoded right before API calls."
        ],
        "data_sources": "File: File Metadata, Module: Module Load, Process: OS API Execution",
        "log_sources": [
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Module", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Loaded DLLs", "location": "Memory", "identify": "Manually loaded modules via LoadLibrary"},
            {"type": "Memory Dumps", "location": "Runtime process memory", "identify": "Decoded or resolved API names"},
            {"type": "Process List", "location": "Task Manager, Sysmon", "identify": "Processes dynamically resolving APIs"}
        ],
        "destination_artifacts": [
            {"type": "Sysmon Logs", "location": "Microsoft-Windows-Sysmon/Operational", "identify": "LoadImage or ImageLoad events"},
            {"type": "Windows Defender Logs", "location": "C:\\ProgramData\\Microsoft\\Windows Defender\\", "identify": "Suspicious modules loaded"},
            {"type": "Windows Error Reporting (WER)", "location": "C:\\ProgramData\\Microsoft\\Windows\\WER", "identify": "Crash data due to incorrect API resolution"}
        ],
        "detection_methods": [
            "Heuristics based on sequence of LoadLibrary and GetProcAddress usage",
            "Signature-based detection of common API hashing routines",
            "YARA rules matching packed/unpacked memory patterns"
        ],
        "apt": [
            "ROADSWEEP", "Raccoon", "Lazarus", "ToddyCat", "AvosLocker", "Bazar"
        ],
        "spl_query": [
            'index=sysmon EventCode=7 OR EventCode=1\n| search ImageLoaded=*kernel32.dll OR *ntdll.dll\n| stats count by process_name, ImageLoaded',
            'index=sysmon EventCode=10\n| search SourceImage=*\\*.exe AND TargetImage=*LoadLibrary*\n| table _time, SourceImage, TargetImage'
        ],
        "hunt_steps": [
            "Look for calls to LoadLibrary or GetProcAddress in unusual processes",
            "Hunt for obfuscated strings that may correspond to hashed API names",
            "Analyze memory of suspicious processes to detect runtime API resolution"
        ],
        "expected_outcomes": [
            "Identified malware using dynamic resolution to evade static inspection",
            "Mapped malicious functionality resolved only during execution",
            "Correlated process behavior with malicious API activity"
        ],
        "false_positive": "Some legitimate applications may use dynamic API resolution for performance or cross-version compatibility. Context is essential.",
        "clearing_steps": [
            "Terminate and quarantine any suspicious process performing runtime resolution",
            "Dump and analyze memory of affected processes to extract IOCs",
            "Patch or block tools identified abusing dynamic API loading"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1140", "example": "Decoded API names used during runtime"},
            {"tactic": "Execution", "technique": "T1059.003", "example": "Resolved API used in command execution"}
        ],
        "watchlist": [
            "Processes loading DLLs dynamically using hashes or encoded strings",
            "Suspicious uses of `GetProcAddress`, `LoadLibrary`, and `VirtualAlloc`",
            "Indicators of packed binaries with low static imports"
        ],
        "enhancements": [
            "Enable AMSI and script block logging to catch malicious code before API resolution",
            "Use memory scanning tools to detect decoded API strings in-process",
            "Deploy behavioral rules to correlate dynamic loading patterns"
        ],
        "summary": "Dynamic API Resolution allows adversaries to obfuscate malicious code by resolving function calls at runtime, bypassing static detections.",
        "remediation": "Monitor and block suspicious use of API resolution functions and use behavior-based detection tools that can analyze runtime activity.",
        "improvements": "Add detection rules for custom API hashing algorithms and automate scanning of decoded runtime strings.",
        "mitre_version": "16.1"
    }
