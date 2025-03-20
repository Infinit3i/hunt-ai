def get_content():
    """
    Returns structured content for the Data Encrypted for Impact (T1486) technique.
    """
    return {
        "id": "T1486",
        "url_id": "T1486",
        "title": "Data Encrypted for Impact",
        "description": "Adversaries may encrypt data on target systems or networks to interrupt availability, often demanding ransom for decryption. They may also destroy keys to render data permanently inaccessible.",  # Simple description (one pair of quotes)
        "tags": [
            "Data Encrypted for Impact",
            "Ransomware",
            "Encryption",
            "Worm-like Propagation",
            "MBR Encryption",
            "Cloud Storage",
            "Extortion",
            "Availability",
            "Impact",
            "File System"
        ],
        "tactic": "Impact",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "IaaS, Linux, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Monitor process execution for vssadmin, wbadmin, bcdedit, and other utilities commonly abused for encryption or data destruction",
            "Track large volumes of file modifications and newly created ransom note files",
            "Watch for unusual kernel driver installation and suspicious admin share access",
            "In cloud environments, monitor for anomalous changes to storage objects or replaced copies"
        ],
        "data_sources": "Cloud Storage, Command, File, Network Share, Process",  # Relevant data sources
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
