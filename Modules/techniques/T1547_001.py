def get_content():
    return {
        "id": "T1547.001",
        "url_id": "T1547/001",
        "title": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "data_sources": "Windows Registry, File Monitoring, Process Execution, Windows Event Logs",
        "protocol": "N/A",
        "os": "Windows",
        "objective": "Detect and mitigate adversaries leveraging Registry Run keys or the Startup folder to execute malicious code on system boot or user logon.",
        "scope": "Monitor registry changes and modifications to the Startup folder for unauthorized entries.",
        "threat_model": "Adversaries may persist on a system by adding executable files or scripts to the Windows Registry Run keys or the Startup folder, ensuring execution at boot or logon.",
        "hypothesis": [
            "Are unauthorized programs executing at system startup or user logon?",
            "Are registry keys being modified to insert persistence mechanisms?",
            "Are adversaries leveraging the Startup folder for automatic execution?"
        ],
        "log_sources": [
            {"type": "Windows Registry", "source": "Sysmon Event ID 13, Windows Event Logs 4657"},
            {"type": "File Monitoring", "source": "Sysmon Event ID 11, File Integrity Monitoring (FIM)"},
            {"type": "Process Execution", "source": "Sysmon Event ID 1, Windows Event Logs 4688"}
        ],
        "detection_methods": [
            "Monitor modifications to registry keys: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run and HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.",
            "Detect unauthorized additions to the Startup folder in %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup.",
            "Analyze process execution from autostart locations for anomalies."
        ],
        "spl_query": ["index=windows EventCode=4657 RegistryPath IN ('HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run')"],
        "hunt_steps": [
            "Run queries in SIEM to detect registry modifications and Startup folder changes.",
            "Correlate with threat intelligence feeds for known persistence mechanisms.",
            "Investigate process execution events related to modified registry keys or Startup folder entries.",
            "Check user activity logs to determine whether changes were authorized.",
            "Validate and escalate if unauthorized persistence mechanisms are found."
        ],
        "expected_outcomes": [
            "Persistence Mechanism Detected: Remove unauthorized registry entries and Startup folder modifications.",
            "No Malicious Activity Found: Improve detection baselines and refine alerting thresholds."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1547.001 (Registry Run Keys / Startup Folder)", "example": "Malware uses registry keys for persistence."},
            {"tactic": "Privilege Escalation", "technique": "T1548 (Abuse Elevation Control Mechanism)", "example": "Attackers escalate privileges using persistent execution."}
        ],
        "watchlist": [
            "Monitor Windows Registry Run keys for unauthorized modifications.",
            "Detect new files appearing in the Startup folder that do not match baseline applications.",
            "Investigate parent-child process relationships originating from autostart locations."
        ],
        "enhancements": [
            "Restrict modification access to registry keys commonly used for persistence.",
            "Implement file integrity monitoring (FIM) on Startup folder directories.",
            "Use Group Policy to block execution from unauthorized autostart locations."
        ],
        "summary": "Detect unauthorized persistence mechanisms using registry keys and the Startup folder.",
        "remediation": "Remove unauthorized registry keys and Startup folder entries, revoke compromised credentials, and improve monitoring.",
        "improvements": "Strengthen endpoint monitoring, apply least-privilege principles, and enforce application control policies."
    }
