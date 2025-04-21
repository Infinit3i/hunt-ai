def get_content():
    return {
        "id": "T1574.002",
        "url_id": "T1574/002",
        "title": "Hijack Execution Flow: DLL Side-Loading",
        "description": "Adversaries may execute their own malicious payloads by side-loading DLLs. This technique is similar to DLL Search Order Hijacking, but instead of waiting for a legitimate application to be invoked, adversaries may deliver both a legitimate signed application and a malicious DLL that the application loads. DLL side-loading abuses the fact that many Windows applications load DLLs from their own directory before checking other system locations.\n\nThis is often done to evade detection by executing code under a trusted application's context. The adversary places a malicious DLL in the same folder as the trusted executable and runs the executable, which unknowingly loads and executes the attacker's DLL. The malicious payload may be obfuscated or encrypted to bypass security mechanisms until it's loaded into memory by the host process.",
        "tags": ["Windows", "DLL Side-Loading", "Execution Hijack", "Defense Evasion", "Persistence"],
        "tactic": "Defense Evasion, Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor system directories for new DLL files appearing outside of updates.",
            "Compare loaded DLLs against known good baselines to detect anomalies.",
            "Enable logging for process creation and DLL loading events in Windows Defender." 
        ],
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Security.evtx", "destination": "System.evtx"},
            {"type": "File Monitoring", "source": "Sysmon Event ID 7", "destination": "Windows Defender"},
            {"type": "Process Execution", "source": "Sysmon Event ID 1", "destination": "Windows Defender"}
        ],
        "source_artifacts": [
            {"type": "File System", "location": "C:\\Windows\\System32", "identify": "Unauthorized DLL modifications"}
        ],
        "destination_artifacts": [
            {"type": "Process Execution", "location": "C:\\Program Files", "identify": "Injected or hijacked DLLs"}
        ],
        "detection_methods": [
            "Monitor file creation in critical directories like System32 and Program Files.",
            "Track process execution chains for unexpected DLL loads.",
            "Use Sysmon Event ID 7 to detect unusual DLL loading behavior."
        ],
        "apt": ["APT10", "TA416", "Sidewinder", "MUSTANG PANDA", "APT41", "PlugX", "LookBack", "Darkgate", "Cobalt Kitty"],
        "spl_query": [
            "index=windows EventCode=7 | table Time, ProcessName, DLLPath",
            "index=windows EventCode=1 ImagePath=*\\*.dll | where ParentProcessName!=KnownProcesses"
        ],
        "hunt_steps": [
            "Identify DLLs loaded from non-standard directories.",
            "Correlate process execution with DLL loading events.",
            "Investigate unauthorized or unsigned DLL files."
        ],
        "expected_outcomes": [
            "Malicious DLL identified and removed.",
            "Legitimate DLLs verified, improving monitoring baseline."
        ],
        "false_positive": "Legitimate software updates may introduce new DLL files in monitored locations.",
        "clearing_steps": [
            "Delete unauthorized DLLs from system directories.",
            "Restore valid DLLs from trusted sources.",
            "Investigate associated processes for further compromise."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1203 (Exploitation for Client Execution)", "example": "Attackers exploit DLL search order vulnerabilities."}
        ],
        "watchlist": [
            "Monitor high-risk applications for unauthorized DLL loads.",
            "Track newly introduced DLLs in critical system paths."
        ],
        "enhancements": [
            "Implement application whitelisting to prevent unauthorized DLL loading.",
            "Enable DLL verification mechanisms in Windows Defender."
        ],
        "summary": "DLL Hijacking can be used by attackers to gain persistence, privilege escalation, or evade detection.",
        "remediation": "Identify and remove unauthorized DLLs, update system security policies, and improve monitoring techniques.",
        "improvements": "Enhance endpoint protection to detect and block unauthorized DLL loading events."
    }
