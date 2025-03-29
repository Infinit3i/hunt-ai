def get_content():
    return {
        "id": "T1218.014",
        "url_id": "T1218/014",
        "title": "System Binary Proxy Execution: MMC",
        "description": "Adversaries may abuse mmc.exe to proxy execution of malicious .msc files. Microsoft Management Console (MMC) is a signed Windows binary used to load snap-ins and configuration tools via .msc files.",
        "tags": ["mmc", "msc", "proxy execution", "CLSID", "signed binary", "defense evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Alert on usage of non-standard or non-Microsoft .msc files.",
            "Verify any custom .msc files being used in environments without documented administrative needs.",
            "Inspect CLSID registry entries invoked by custom .msc files for malicious linkage."
        ],
        "data_sources": "Command, File, Process",
        "log_sources": [
            {"type": "Command", "source": "Sysmon", "destination": ""},
            {"type": "File", "source": "Windows Security", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Sysmon Logs", "location": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx", "identify": "Event ID 1 (Process Creation) with mmc.exe and custom .msc file"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor command-line usage of mmc.exe with non-standard .msc paths",
            "Detect creation of custom .msc files containing suspicious snap-ins or embedded CLSIDs",
            "Alert on usage of '-Embedding' argument with unknown .msc files"
        ],
        "apt": [
            "FIN7", "APT19", "TA505"
        ],
        "spl_query": [
            "index=sysmon EventCode=1 Image=*\\mmc.exe\n| search CommandLine=\"*.msc\"\n| stats count by CommandLine, ParentImage, User",
            "index=windows source=\"WinEventLog:Security\" EventCode=4688 NewProcessName=*mmc.exe*\n| stats count by CommandLine, AccountName"
        ],
        "hunt_steps": [
            "Identify execution of MMC with custom .msc files",
            "Check registry for malicious CLSIDs referenced in custom .msc snap-ins",
            "Inspect content of suspicious .msc files on disk"
        ],
        "expected_outcomes": [
            "Detection of MMC executing weaponized management consoles",
            "Identification of custom .msc files linked to adversary payloads",
            "Increased visibility into Windows management utility misuse"
        ],
        "false_positive": "Administrators may use custom .msc files for legitimate system configuration tasks. Validate source and intent.",
        "clearing_steps": [
            "taskkill /IM mmc.exe /F",
            "Delete any unauthorized or malicious .msc files",
            "Clean up related CLSID registry keys under HKEY_CLASSES_ROOT or HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059.001", "example": "Malicious script invoked through custom snap-in"},
            {"tactic": "Persistence", "technique": "T1546.015", "example": "Abuse of CLSID via MMC for persistence"},
            {"tactic": "Impact", "technique": "T1490", "example": "Backup catalog deletion using wbadmin.msc"}
        ],
        "watchlist": [
            "MMC launching with non-Microsoft .msc file",
            "Processes spawned from mmc.exe unexpectedly",
            "New .msc files written to user or temp directories"
        ],
        "enhancements": [
            "Enforce AppLocker or WDAC policies to restrict custom .msc usage",
            "Enable script block and command-line logging for MMC-related activities",
            "Monitor registry changes for CLSID insertions"
        ],
        "summary": "MMC.exe is a trusted binary used for system configuration, but adversaries can abuse it by executing custom .msc files tied to malicious CLSIDs or commands to evade detection and achieve execution or impact.",
        "remediation": "Restrict creation and execution of unauthorized .msc files. Review registry CLSID references and block known abuse vectors using Windows Defender Application Control.",
        "improvements": "Improve alerting for MMC usage involving suspicious .msc files, especially when used with '-Embedding'. Enhance detection through registry monitoring and audit policy coverage.",
        "mitre_version": "16.1"
    }
