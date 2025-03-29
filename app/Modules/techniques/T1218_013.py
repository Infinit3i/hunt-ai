def get_content():
    return {
        "id": "T1218.013",
        "url_id": "T1218/013",
        "title": "System Binary Proxy Execution: Mavinject",
        "description": "Adversaries may abuse mavinject.exe to proxy execution of malicious code. Mavinject.exe is the Microsoft Application Virtualization Injector, a Windows utility that can inject code into external processes as part of Microsoft Application Virtualization (App-V).",
        "tags": ["mavinject", "dll injection", "code injection", "signed binary", "proxy execution", "defense evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor for mavinject.exe usage with uncommon process IDs or unknown DLL paths.",
            "Search for the /INJECTRUNNING or /HMODULE switches as key indicators.",
            "Correlate mavinject activity with suspicious child process behavior or network activity."
        ],
        "data_sources": "Command, Process",
        "log_sources": [
            {"type": "Command", "source": "Sysmon", "destination": ""},
            {"type": "Process", "source": "Windows Security", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Sysmon Logs", "location": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx", "identify": "Event ID 1 (Process Creation), arguments with /INJECTRUNNING or /HMODULE"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Track mavinject.exe usage with command-line arguments for DLL injection",
            "Monitor target process behavior post-injection for signs of malicious actions",
            "Correlate with image load events or module base address changes"
        ],
        "apt": [
            "Lazarus", "FIN7", "APT41"
        ],
        "spl_query": [
            "index=sysmon EventCode=1 Image=*\\mavinject.exe\n| search CommandLine=\"*INJECTRUNNING*\" OR CommandLine=\"*HMODULE*\"\n| stats count by CommandLine, TargetImage, User",
            "index=windows source=\"WinEventLog:Security\" EventCode=4688 NewProcessName=*mavinject.exe*\n| stats count by CommandLine, ParentProcessName"
        ],
        "hunt_steps": [
            "Search for mavinject.exe usage with non-standard DLLs in user directories",
            "Inspect command-line arguments involving /INJECTRUNNING or /HMODULE",
            "Monitor for changes in behavior of injected target processes"
        ],
        "expected_outcomes": [
            "Detection of DLL injection via mavinject.exe into legitimate processes",
            "Visibility into evasion techniques leveraging signed binaries",
            "Enhanced logging for code injection artifacts"
        ],
        "false_positive": "Mavinject.exe may be used by Microsoft App-V under valid conditions. Verify PID and DLL legitimacy before triggering alerts.",
        "clearing_steps": [
            "taskkill /IM mavinject.exe /F",
            "Review injected process and unload injected DLL if applicable using task manager or handle tools",
            "Clear any malicious DLLs or registry persistence mechanisms used in conjunction"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1055.001", "example": "DLL injection using mavinject.exe with INJECTRUNNING"},
            {"tactic": "Execution", "technique": "T1203", "example": "Injection of code into trusted processes for execution"},
            {"tactic": "Persistence", "technique": "T1546", "example": "Injected DLL set to autoload via registry or scheduled task"}
        ],
        "watchlist": [
            "Mavinject.exe with /INJECTRUNNING or /HMODULE",
            "DLLs written to temp or user-writable directories prior to injection",
            "Injected processes exhibiting anomalous behavior"
        ],
        "enhancements": [
            "Deploy rules to detect use of uncommon arguments to mavinject.exe",
            "Implement EDR alerts for process injection events with Microsoft-signed binaries",
            "Correlate mavinject.exe executions with real-time memory analysis tools"
        ],
        "summary": "Mavinject.exe is a signed Windows binary that can be abused by adversaries to inject code into other processes. This proxy execution can bypass defenses and mask malicious activity under a legitimate process context.",
        "remediation": "Restrict mavinject.exe usage where App-V is not deployed. Monitor injection behavior and review DLL origin paths. Deploy behavioral EDR rules for injection indicators.",
        "improvements": "Enhance visibility with detailed command-line logging, kernel callbacks for injection, and correlation between source and injected processes.",
        "mitre_version": "16.1"
    }
