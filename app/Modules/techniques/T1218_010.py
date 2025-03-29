def get_content():
    return {
        "id": "T1218.010",
        "url_id": "T1218/010",
        "title": "System Binary Proxy Execution: Regsvr32",
        "description": "Adversaries may abuse Regsvr32.exe to proxy execution of malicious code. Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems.",
        "tags": ["regsvr32", "Squiblydoo", "signed binary", "proxy execution", "defense evasion"],
        "tactic": "Defense Evasion",
        "protocol": "HTTP",
        "os": "Windows",
        "tips": [
            "Compare regsvr32.exe arguments to known-good baselines",
            "Enable command-line logging (e.g., via Sysmon or Windows 4688 events)",
            "Monitor for regsvr32 usage from uncommon parent processes"
        ],
        "data_sources": "Command, Module, Network Traffic, Process",
        "log_sources": [
            {"type": "Command", "source": "Sysmon", "destination": ""},
            {"type": "Process", "source": "Windows Security", "destination": ""},
            {"type": "Network Traffic", "source": "Sysmon", "destination": ""},
            {"type": "Module", "source": "Sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Sysmon Logs", "location": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx", "identify": "Event ID 1 (Process Creation), Event ID 7 (Image Load), Event ID 3 (Network Connection)"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor process creation logs for regsvr32.exe with suspicious command-line arguments",
            "Alert on regsvr32.exe reaching out to remote URLs",
            "Baseline legitimate regsvr32.exe usage across the environment"
        ],
        "apt": [
            "APT19", "OceanLotus", "EvilNum", "Valak", "Cobalt Group", "Qakbot", "Saint Bot", "Squirrelwaffle", "Black Basta", "MuddyWater", "Raspberry Robin", "Cobalt Kitty", "Qbot", "Dridex", "DarkHydrus", "Astaroth", "Mockingbird", "APT32", "Cloud Atlas", "Kimsuky", "INOCNATION"
        ],
        "spl_query": [
            "index=sysmon EventCode=1 Image=*\\regsvr32.exe\n| stats count by ParentImage, CommandLine, User",
            "index=windows source=\"WinEventLog:Security\" EventCode=4688 NewProcessName=*regsvr32.exe*\n| stats count by ParentProcessName, CommandLine, AccountName"
        ],
        "hunt_steps": [
            "Search for regsvr32.exe executions with external URLs as arguments",
            "Investigate if COM scriptlets were loaded remotely via .sct files",
            "Identify regsvr32 activity from unusual parent processes"
        ],
        "expected_outcomes": [
            "Detection of regsvr32 abuse for payload delivery",
            "Detection of persistence via COM hijacking",
            "Detection of unusual execution patterns indicating Squiblydoo"
        ],
        "false_positive": "Administrators using regsvr32 for legitimate DLL registration. Validate usage context, parent process, and target DLL.",
        "clearing_steps": [
            "taskkill /IM regsvr32.exe /F",
            "Delete any downloaded .sct or malicious DLLs used in attack",
            "Clear prefetch entries using 'del C:\\Windows\\Prefetch\\REGSVR32*.pf'",
            "Delete any registry keys related to COM hijacking if persistence established"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1546.015", "example": "Component Object Model Hijacking using regsvr32"},
            {"tactic": "Command and Control", "technique": "T1105", "example": "Remote payload via SCT script from a C2"}
        ],
        "watchlist": [
            "regsvr32.exe reaching out to internet",
            ".sct files in unusual directories",
            "regsvr32.exe with no DLL registration but network access"
        ],
        "enhancements": [
            "Apply AppLocker or WDAC policies to restrict regsvr32 execution",
            "Block outbound traffic for regsvr32 if internet access is not required",
            "Integrate alerting for process execution chains involving regsvr32"
        ],
        "summary": "Regsvr32.exe is a trusted Windows binary that can be abused by adversaries to execute arbitrary code without writing to disk or altering the registry, often bypassing security tools.",
        "remediation": "Restrict regsvr32 usage via AppLocker or Windows Defender Application Control. Monitor logs for anomalies. Educate users on phishing vectors that abuse regsvr32.",
        "improvements": "Enhance detection by correlating regsvr32 with network and module loads. Alert on regsvr32 calling external resources or executing outside expected contexts.",
        "mitre_version": "16.1"
    }
