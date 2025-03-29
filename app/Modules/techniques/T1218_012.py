def get_content():
    return {
        "id": "T1218.012",
        "url_id": "T1218/012",
        "title": "System Binary Proxy Execution: Verclsid",
        "description": "Adversaries may abuse verclsid.exe to proxy execution of malicious code. Verclsid.exe is known as the Extension CLSID Verification Host and is responsible for verifying each shell extension before they are used by Windows Explorer or the Windows Shell.",
        "tags": ["verclsid", "COM abuse", "proxy execution", "defense evasion", "LOLBAS"],
        "tactic": "Defense Evasion",
        "protocol": "HTTP",
        "os": "Windows",
        "tips": [
            "Alert if verclsid.exe is spawned by an unusual parent like Microsoft Office.",
            "Monitor verclsid.exe spawning any child process or making network connections.",
            "Compare verclsid.exe arguments to baseline of known legitimate CLSIDs."
        ],
        "data_sources": "Command, Process",
        "log_sources": [
            {"type": "Command", "source": "Sysmon", "destination": ""},
            {"type": "Process", "source": "Windows Security", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Sysmon Logs", "location": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx", "identify": "Event ID 1 (Process Creation)"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor execution of verclsid.exe and compare with normal usage patterns",
            "Detect suspicious command-line usage such as '/S /C {CLSID}'",
            "Alert on unexpected parent-child process chains involving verclsid.exe"
        ],
        "apt": [
            "Raspberry Robin", "Qakbot", "Cobalt Kitty", "FIN8", "APT19", "TA505"
        ],
        "spl_query": [
            "index=sysmon EventCode=1 Image=*\\verclsid.exe\n| stats count by CommandLine, ParentImage, User",
            "index=windows source=\"WinEventLog:Security\" EventCode=4688 NewProcessName=*verclsid.exe*\n| stats count by CommandLine, ParentProcessName"
        ],
        "hunt_steps": [
            "Identify instances of verclsid.exe with unusual or rare CLSIDs",
            "Search for network connections initiated by verclsid.exe",
            "Investigate verclsid.exe execution from Office applications or documents"
        ],
        "expected_outcomes": [
            "Detection of COM abuse using verclsid.exe as a proxy",
            "Exposure of misused signed binaries for scriptlet or payload execution",
            "Improved understanding of application control bypass via LOLBAS"
        ],
        "false_positive": "Verclsid.exe may execute during normal shell extension verification. Validate CLSID legitimacy and execution context.",
        "clearing_steps": [
            "taskkill /IM verclsid.exe /F",
            "Investigate and remove unauthorized COM objects or related registry entries",
            "Use Autoruns to identify and disable suspicious shell extensions"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059.005", "example": "Remote scriptlet execution via COM object"},
            {"tactic": "Persistence", "technique": "T1546.015", "example": "Persistence using COM Hijacking via verclsid"},
            {"tactic": "Masquerading", "technique": "T1036", "example": "Signed binary misused to bypass defenses"}
        ],
        "watchlist": [
            "Verclsid.exe spawned from Office applications",
            "Command-line arguments containing suspicious CLSIDs or /S /C switches",
            "Verclsid.exe initiating network connections"
        ],
        "enhancements": [
            "Limit verclsid.exe execution using WDAC or AppLocker rules",
            "Add visibility by logging shell extension usage and COM object loads",
            "Enrich process telemetry with CLSID resolution for context"
        ],
        "summary": "Verclsid.exe is a signed Windows utility used to verify shell extensions. Adversaries can exploit it to proxy the execution of COM-based payloads or remotely loaded scriptlets, bypassing some security controls.",
        "remediation": "Implement AppLocker rules to block verclsid misuse. Monitor execution chains and investigate shell extension or COM-related anomalies.",
        "improvements": "Correlate verclsid.exe usage with COM CLSID resolution and registry loads. Improve anomaly detection for signed binary misuse.",
        "mitre_version": "16.1"
    }
