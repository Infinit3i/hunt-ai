def get_content():
    return {
        "id": "T1137.002",
        "url_id": "T1137/002",
        "title": "Office Application Startup: Office Test",
        "description": "Adversaries may abuse the Microsoft Office \"Office Test\" Registry key to achieve persistence by configuring a malicious DLL to be loaded whenever an Office application starts. This key is used for development and debugging purposes and is not created by default.",
        "tags": ["persistence", "office", "dll", "registry", "startup", "office test"],
        "tactic": "persistence",
        "protocol": "",
        "os": "Office Suite, Windows",
        "tips": [
            "Monitor for creation of the `Office test\\Special\\Perf` registry keys under HKCU and HKLM",
            "Use Sysmon to detect unusual DLL loads by Office applications",
            "Alert on non-standard Office behavior in systems not used for development"
        ],
        "data_sources": "Command, File, Module, Process, Windows Registry",
        "log_sources": [
            {"type": "Windows Registry", "source": "Sysmon", "destination": ""},
            {"type": "Module", "source": "Sysmon", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Registry Key", "location": "HKCU\\Software\\Microsoft\\Office test\\Special\\Perf", "identify": "DLL path in user context"},
            {"type": "Registry Key", "location": "HKLM\\Software\\Microsoft\\Office test\\Special\\Perf", "identify": "DLL path in system context"},
            {"type": "Prefetch Files", "location": "C:\\Windows\\Prefetch", "identify": "Office apps loading non-standard DLLs"}
        ],
        "destination_artifacts": [
            {"type": "DLL File", "location": "Custom or temp directory", "identify": "Malicious payload loaded at Office launch"},
            {"type": "Windows Registry", "location": "HKCU or HKLM paths", "identify": "DLL path registration"},
            {"type": "Process", "location": "Office.exe child processes", "identify": "Spawned from Office after DLL injection"}
        ],
        "detection_methods": [
            "Detect creation or modification of the `Office test\\Special\\Perf` registry keys",
            "Alert on Office processes loading unusual DLLs not typically associated with Office",
            "Use Autoruns to monitor Office test registry locations"
        ],
        "apt": [
            "Sofacy (APT28)"
        ],
        "spl_query": [
            'index=wineventlog OR index=sysmon \n(EventCode=12 OR EventCode=13) \n| search TargetObject="*\\Office test\\Special\\Perf"',
            'index=sysmon EventCode=7 \n| search ImageLoaded="*\\*.dll" \n| search Image="*\\WINWORD.EXE" OR Image="*\\EXCEL.EXE"',
            'index=autoruns source="Office Test" \n| stats count by ImagePath, EntryLocation'
        ],
        "hunt_steps": [
            "Search registry for presence of Office test keys",
            "Identify DLLs loaded by Office processes not in expected paths",
            "Check Autoruns output for Office-related entries not signed by Microsoft"
        ],
        "expected_outcomes": [
            "Persistence achieved through DLL loaded by Office processes",
            "Execution of arbitrary payload without user interaction",
            "DLL loading observed on every Office launch"
        ],
        "false_positive": "Office developers may use this key legitimately in test environments. Validate path and file signatures.",
        "clearing_steps": [
            "Delete the `Office test\\Special\\Perf` registry key",
            "Remove any associated DLLs",
            "Reboot system or terminate Office processes to stop malicious DLL from being used"
        ],
        "mitre_mapping": [
            {"tactic": "persistence", "technique": "T1137", "example": "DLL persistence via Office Test registry key"},
            {"tactic": "execution", "technique": "T1055.001", "example": "DLL loaded into Office process at runtime"},
            {"tactic": "defense-evasion", "technique": "T1574.002", "example": "Hijacking Office startup mechanism"}
        ],
        "watchlist": [
            "Uncommon DLL paths associated with Office",
            "Presence of Office test registry keys in user or system hives",
            "Office processes spawning unexpected binaries"
        ],
        "enhancements": [
            "Restrict write access to Office registry paths",
            "Use AppLocker to restrict DLL execution from non-standard directories",
            "Log and alert on Office processes performing DLL loads from suspicious locations"
        ],
        "summary": "Malicious use of the Office Test registry key allows persistent code execution via DLL injection when Office applications are opened.",
        "remediation": "Remove malicious registry entries and DLLs, monitor Office registry keys, and deploy DLL whitelisting policies.",
        "improvements": "Use Sysmon and Autoruns to proactively detect unauthorized startup entries. Harden Office launch behavior via GPO.",
        "mitre_version": "16.1"
    }
