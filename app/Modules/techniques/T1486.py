def get_content():
    """
    Returns structured content for the Data Encrypted for Impact (T1486) technique.
    """
    return {
        "id": "T1486",
        "url_id": "T1486",
        "title": "Data Encrypted for Impact",
        "tactic": "Impact",
        "data_sources": "File monitoring, Process monitoring, Windows Event Logs, Endpoint Detection and Response (EDR)",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries encrypt files on a victim's system to disrupt operations and demand ransom payments.",
        "scope": "Detect unauthorized encryption activities and prevent ransomware attacks.",
        "threat_model": "Attackers deploy ransomware to encrypt valuable files and demand payment for decryption keys.",
        "hypothesis": [
            "Are critical files being encrypted by unexpected processes?",
            "Are backup files being deleted or modified in correlation with file encryption?",
            "Are systems showing signs of unauthorized encryption tools being executed?"
        ],
        "tips": [
            "Monitor file access patterns to detect rapid encryption of multiple files.",
            "Alert on unexpected mass file renaming or extensions commonly used in ransomware attacks (e.g., .locked, .crypt).",
            "Use behavioral analysis tools to detect ransomware-like behavior."
        ],
        "log_sources": [
            {"type": "File Monitoring", "source": "Sysmon Event ID 11 (File Creation)", "destination": "EDR Alerts"},
            {"type": "Process Monitoring", "source": "Sysmon Event ID 1 (Process Creation)", "destination": "Security Logs"},
            {"type": "Windows Event Logs", "source": "Security Event 4663 (File Access)", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "File", "location": "C:\\Users\\Public\\", "identify": "Encrypted files with unusual extensions"}
        ],
        "destination_artifacts": [
            {"type": "Process Execution", "location": "C:\\Windows\\System32", "identify": "Suspicious PowerShell or script executions"}
        ],
        "detection_methods": [
            "Monitor file modification rates to detect ransomware-like activity.",
            "Track suspicious use of PowerShell, WMI, or scripting tools related to file encryption.",
            "Detect attempts to disable antivirus or security tools."
        ],
        "apt": ["G0032", "G0051", "G0079"],
        "spl_query": [
            "index=windows EventCode=4663 | stats count by ObjectName, ProcessName",
            "index=windows EventCode=1 (Process Creation) | search ransomware_indicator"
        ],
        "hunt_steps": [
            "Search for signs of mass file encryption in file monitoring logs.",
            "Identify unauthorized modifications to security settings or backups.",
            "Trace the origin of suspicious processes executing encryption commands."
        ],
        "expected_outcomes": [
            "Ransomware attack detected early, preventing widespread encryption.",
            "No unauthorized encryption detected, improving baseline monitoring."
        ],
        "false_positive": "Automated backup or compression tools may mimic ransomware behavior.",
        "clearing_steps": [
            "Terminate malicious processes executing ransomware payloads.",
            "Restore files from secure, offline backups.",
            "Conduct forensic analysis to identify attack vectors and entry points."
        ],
        "mitre_mapping": [
            {"tactic": "Impact", "technique": "T1485 (Data Destruction)", "example": "Attackers may delete backups before encrypting files."}
        ],
        "watchlist": [
            "Monitor for unusual file extensions indicating encryption.",
            "Alert on unauthorized access to shadow copies and backup folders."
        ],
        "enhancements": [
            "Deploy endpoint protection with ransomware behavior detection.",
            "Implement network segmentation to contain ransomware spread."
        ],
        "summary": "Attackers encrypt data to disrupt operations and demand ransom payments.",
        "remediation": "Remove malicious payloads, restore files, and strengthen security policies.",
        "improvements": "Enhance monitoring of file modifications and improve incident response readiness."
    }
