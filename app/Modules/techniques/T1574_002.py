def get_content():
    """
    Returns structured content for the DLL Hijacking persistence method.
    """
    return {
        "id": "T1574.002",
        "url_id": "T1574/002",
        "title": "DLL Hijacking",
        "tactic": "Persistence, Privilege Escalation, Defense Evasion",
        "data_sources": "Windows Event Logs, File Monitoring, Process Execution",
        "protocol": "N/A",
        "os": "Windows",
        "objective": "Adversaries may execute malicious payloads by hijacking DLL search order loading mechanisms.",
        "scope": "Monitor DLL loading events and analyze execution paths for unauthorized modifications.",
        "threat_model": "Attackers may replace or introduce malicious DLLs in locations where trusted applications load them, enabling privilege escalation and persistence.",
        "hypothesis": [
            "Are there unauthorized DLLs loaded by legitimate processes?",
            "Are newly created DLLs appearing in system directories?",
            "Is an attacker using DLL hijacking for persistence or privilege escalation?"
        ],
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
        "apt": ["G0016", "G0045"],
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
