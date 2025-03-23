def get_content():
    return {
        "id": "T1546.007",
        "url_id": "T1546/007",
        "title": "Event Triggered Execution: Netsh Helper DLL",
        "description": "Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs.",
        "tags": ["persistence", "privilege escalation", "netsh", "dll injection", "registry"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor the HKLM\\SOFTWARE\\Microsoft\\Netsh registry key for changes.",
            "Flag netsh.exe spawning child processes as suspicious.",
            "Correlate registry additions with DLL file path reputation."
        ],
        "data_sources": "Command, Module, Process, Windows Registry",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Module", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Registry Hives (SYSTEM)", "location": "HKLM\\SOFTWARE\\Microsoft\\Netsh", "identify": "Presence of unknown or suspicious DLL paths as helper libraries."},
            {"type": "Loaded DLLs", "location": "", "identify": "DLLs loaded by netsh.exe that are not part of default configuration."},
            {"type": "Process List", "location": "", "identify": "Look for netsh.exe with unusual child processes."}
        ],
        "destination_artifacts": [
            {"type": "", "location": "", "identify": ""}
        ],
        "detection_methods": [
            "Registry key modification monitoring",
            "Monitoring netsh.exe for unusual DLL loads",
            "Detecting netsh.exe spawning child processes"
        ],
        "apt": ["APT29", "FIN7"],
        "spl_query": [
            "index=win_logs source=WinRegistry RegistryKeyPath=\"HKLM\\SOFTWARE\\Microsoft\\Netsh\" ",
            "index=win_logs source=Sysmon EventCode=1 Image=\"*netsh.exe\" \
| stats count by ParentImage, CommandLine"
        ],
        "hunt_steps": [
            "Query registry for helper DLLs in Netsh key.",
            "Review netsh.exe execution logs for anomalies.",
            "Use memory analysis to identify non-standard DLLs loaded by netsh.exe."
        ],
        "expected_outcomes": [
            "Detection of unauthorized Netsh Helper DLL registration.",
            "Identification of abnormal child processes from netsh.exe."
        ],
        "false_positive": "Legitimate software (e.g., VPN clients) may register Netsh helpers.",
        "clearing_steps": [
            "reg delete HKLM\\SOFTWARE\\Microsoft\\Netsh /f",
            "Remove malicious DLL from disk (e.g., del C:\\malicious.dll)",
            "Restart system or stop any service utilizing netsh with malicious config"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1218", "example": "Hijacking Netsh for malicious DLL loading."}
        ],
        "watchlist": [
            "Any modification to Netsh registry keys",
            "DLLs dropped in system32 or unusual directories tied to netsh"
        ],
        "enhancements": [
            "Use AppLocker or WDAC to block unsigned DLLs from loading into netsh.exe",
            "Implement EDR alerts for netsh behavior deviation"
        ],
        "summary": "This technique exploits Netsh helper DLL registration for persistence and privilege escalation.",
        "remediation": "Remove suspicious DLLs and registry entries, block unauthorized netsh.exe usage via security controls.",
        "improvements": "Deploy continuous registry monitoring and enforce strict DLL signature policies.",
        "mitre_version": "16.1"
    }