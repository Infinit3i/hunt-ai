def get_content():
    """
    Returns structured content for the Rundll32 abuse method.
    """
    return {
        "id": "T1218.011",
        "url_id": "T1218/011",
        "title": "System Binary Proxy Execution: Rundll32",
        "description": "Adversaries may abuse rundll32.exe to proxy execution of malicious code. Using rundll32.exe, vice executing directly, may avoid triggering security tools that may not monitor execution of the rundll32.exe process due to allowlists or false positives.",
        "tags": ["rundll32", "proxy execution", "defense evasion", "signed binary", "masquerading", "script execution"],
        "tactic": "Defense Evasion",
        "protocol": "HTTP",
        "os": "Windows",
        "tips": [
            "Monitor rundll32 executions that involve external URLs or scriptlet objects.",
            "Track unusual DLL function names, including those using Unicode/ANSI suffixes (W/A).",
            "Look for rundll32 spawning from uncommon or user-facing applications."
        ],
        "data_sources": "Command, File, Module, Process",
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Security.evtx", "destination": "System.evtx"},
            {"type": "Process Monitoring", "source": "Sysmon Event ID 1, Event ID 10"},
            {"type": "File Monitoring", "source": "Sysmon Event ID 11"}
        ],
        "source_artifacts": [
            {"type": "Process Execution", "location": "C:\\Windows\\System32\\rundll32.exe", "identify": "Unusual arguments or DLL locations"}
        ],
        "destination_artifacts": [
            {"type": "DLL Files", "location": "C:\\Users\\Public", "identify": "Suspicious DLL executions"}
        ],
        "detection_methods": [
            "Monitor command-line usage of rundll32.exe for abnormal parameters.",
            "Detect rundll32.exe spawning child processes that are not standard.",
            "Alert on rundll32.exe execution from non-standard directories."
        ],
        "apt": [
            "Sofacy", "APT19", "APT29", "TA505", "Gamaredon", "Qakbot", "FIN8", "Nobelium", "FIN12", "Lazarus", "Cobalt Kitty", "InvisiMole", "Zebrocy", "Raspberry Robin", "EvilNum", "Turla", "Mockingbird", "Carbanak", "Konni", "Winnti", "SedUploader", "Spalax", "Black Basta"
        ],
        "spl_query": [
            "index=windows ProcessName=rundll32.exe \n| table Time, CommandLine, ParentProcess, ImagePath",
            "index=windows EventCode=4688 NewProcessName=*rundll32.exe* \n| table Time, CommandLine, ParentProcess",
            "index=sysmon EventCode=1 Image=*\\rundll32.exe\n| stats count by CommandLine, ParentImage, User",
            "index=windows source=\"WinEventLog:Security\" EventCode=4688 NewProcessName=*rundll32.exe*\n| stats count by CommandLine, AccountName"
        ],
        "hunt_steps": [
            "Identify instances of rundll32.exe execution with unusual DLL arguments.",
            "Investigate rundll32.exe launching non-standard processes.",
            "Correlate rundll32.exe activity with suspicious file creation events."
        ],
        "expected_outcomes": [
            "Malicious rundll32.exe execution detected and mitigated.",
            "No suspicious rundll32.exe usage found, improving detection baselines."
        ],
        "false_positive": "Legitimate software and Windows updates may use rundll32.exe for execution.",
        "clearing_steps": [
            "Taskkill /IM rundll32.exe /F",
            "Delete any unauthorized DLL files loaded via rundll32.exe."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1202 (Indirect Command Execution)", "example": "Attackers use rundll32.exe to execute payloads covertly."}
        ],
        "watchlist": [
            "Monitor rundll32.exe execution paths and arguments.",
            "Detect rundll32.exe launching unexpected processes."
        ],
        "enhancements": [
            "Restrict rundll32.exe execution using AppLocker or WDAC.",
            "Implement logging and alerts for rundll32.exe abuse."
        ],
        "summary": "Rundll32.exe can be abused by attackers to execute malicious DLLs while evading detection.",
        "remediation": "Restrict rundll32.exe execution to trusted DLLs and monitor its usage closely.",
        "improvements": "Enhance rundll32.exe logging and apply behavior-based detection techniques.",
        "mitre_version": "16.1"
    }
