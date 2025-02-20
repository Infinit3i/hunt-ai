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
        "tips": [
            "Monitor Windows Registry Run keys for unauthorized modifications.",
            "Detect new files appearing in the Startup folder that do not match baseline applications.",
            "Investigate parent-child process relationships originating from autostart locations."
        ],
        "log_sources": [
            {"type": "Windows Registry", "source": "Sysmon Event ID 13, Windows Event Logs 4657", "destination": "SIEM"},
            {"type": "File Monitoring", "source": "Sysmon Event ID 11, File Integrity Monitoring (FIM)", "destination": "Endpoint Security Platform"},
            {"type": "Process Execution", "source": "Sysmon Event ID 1, Windows Event Logs 4688", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "Registry Key", "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "identify": "Persistence via Registry Run Keys"},
            {"type": "File", "location": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "identify": "Malicious file added to Startup folder"}
        ],
        "destination_artifacts": [
            {"type": "Process Execution", "location": "Sysmon Event ID 1", "identify": "Process execution from autostart locations"},
            {"type": "Registry Modification", "location": "Windows Event ID 4657", "identify": "Registry changes to persistence locations"}
        ],
        "detection_methods": [
            "Monitor modifications to registry keys: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run and HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.",
            "Detect unauthorized additions to the Startup folder in %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup.",
            "Analyze process execution from autostart locations for anomalies."
        ],
        "apt": [
            "G0007 - APT28: Known to use registry run keys for persistence.",
            "G0016 - APT29: Uses startup folders to execute malicious payloads at logon."
        ],
        "spl_query": [
            "index=windows EventCode=4657 RegistryPath IN ('HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run')",
            "index=windows EventCode=4688 \n| search ParentImage IN ('C:\\\\Windows\\\\explorer.exe', 'C:\\\\Windows\\\\system32\\\\userinit.exe') \n| stats count by Image, ParentImage"
        ],
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
        "false_positive": "Legitimate software installers and enterprise applications may modify autostart locations for persistence.",
        "clearing_steps": [
            "Remove unauthorized registry keys under Run and RunOnce.",
            "Delete malicious files in the Startup folder.",
            "Revoke compromised credentials and reset account permissions.",
            "Apply registry and file monitoring to prevent future persistence."
        ],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1548 (Abuse Elevation Control Mechanism)", "example": "Attackers escalate privileges using persistent execution."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Adversaries may delete logs related to registry and startup persistence."},
            {"tactic": "Execution", "technique": "T1204.002 (User Execution - Malicious File)", "example": "Adversaries may execute scripts from startup locations."}
        ],
        "watchlist": [
            "New or modified registry keys under Run and RunOnce.",
            "Execution of unusual processes from the Startup folder.",
            "Correlate process lineage from known autostart locations."
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






'''
        {
            "title": "Registry Run Keys",
            "content": """
The most common ASEPs (AutoStart Extension Points) are the “Run” Registry keys:
- NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
- NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
- Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
- Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run

These keys are executed when a user logs on. Monitoring these keys is crucial for detecting persistence mechanisms.
"""
        },
        {
            "title": "Winlogon Userinit",
            "content": """
The Winlogon Userinit key can be used to maintain persistence:
- SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit

This key typically contains:
- C:\\Windows\\system32\\userinit.exe

However, it can be modified to include malicious binaries:
- Example: C:\\Windows\\system32\\userinit.exe,C:\\Temp\\malicious.exe
"""
        },
        {
            "title": "Startup Folder",
            "content": """
The Startup folder allows for persistence by placing shortcuts in this folder:
- %AppData%\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup

Files in this folder automatically execute when a user logs on. Malware often uses this location for persistence.
"""
        },
        {
            "title": "Investigative Notes",
            "content": """
Investigating ASEPs across multiple systems can help identify compromised hosts. Key notes:
- ASEPs are numerous and diverse, requiring thorough examination.
- Tools like Registry Explorer and RegRipper can retrieve additional ASEPs from Registry hives.
- Analyzing data across systems may reveal outliers indicative of malicious activity.
"""
        }
    ]
'''