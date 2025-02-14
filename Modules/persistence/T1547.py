def get_content():
    return {
        "id": "T1547",
        "url_id": "T1547",
        "title": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "data_sources": "Registry, File System, Process Monitoring, Windows Event Logs, Sysmon, EDR",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate persistence mechanisms that leverage system boot or logon processes to execute malicious code.",
        "scope": "Monitor registry keys, startup folder modifications, and scheduled tasks for unauthorized autostart mechanisms.",
        "threat_model": "Adversaries may abuse system autostart execution mechanisms to maintain persistence across reboots or logons.",
        "hypothesis": [
            "Are there unauthorized modifications to startup registry keys or folders?",
            "Are suspicious processes executing during system boot or user logon?",
            "Are scheduled tasks or login scripts being abused for persistence?"
        ],
        "log_sources": [
            {"type": "Registry Monitoring", "source": "Sysmon (Event ID 13 - Registry Modification)"},
            {"type": "File System Monitoring", "source": "Sysmon (Event ID 11 - File Create)"},
            {"type": "Process Execution Logs", "source": "Sysmon (Event ID 1 - Process Creation)"},
            {"type": "Windows Event Logs", "source": "Security Logs (Event ID 4688 - New Process Created)"},
            {"type": "EDR", "source": "CrowdStrike, Defender ATP, Carbon Black"}
        ],
        "detection_methods": [
            "Monitor for changes to common persistence registry keys.",
            "Detect unauthorized file modifications in startup directories.",
            "Identify suspicious processes executing during boot or user login.",
            "Analyze scheduled tasks for anomalous execution patterns."
        ],
        "spl_query": "index=windows EventCode=4657 RegistryPath=\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*\" | stats count by RegistryPath, ProcessName",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1547",
        "hunt_steps": [
            "Run Queries in SIEM: Identify registry modifications, startup folder changes, and scheduled tasks.",
            "Correlate with Threat Intelligence: Check hashes and registry changes against known persistence techniques.",
            "Investigate Process Execution: Analyze suspicious processes executed at boot or logon.",
            "Monitor Scheduled Tasks: Identify unauthorized or unusual task executions.",
            "Validate & Escalate: If persistence is detected, escalate for remediation and containment."
        ],
        "expected_outcomes": [
            "Persistence Mechanism Detected: Remove unauthorized entries and isolate affected systems.",
            "No Malicious Activity Found: Improve detection baselines and enhance monitoring of persistence techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1547 (Boot or Logon Autostart Execution)", "example": "Malware modifying startup registry keys."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Adversaries delete logs to conceal persistence mechanisms."},
            {"tactic": "Privilege Escalation", "technique": "T1068 (Exploiting Privileged Execution)", "example": "Modifications to privileged autostart locations."}
        ],
        "watchlist": [
            "Monitor changes to HKCU\Software\Microsoft\Windows\CurrentVersion\Run.",
            "Detect modifications to startup folders: C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup.",
            "Monitor scheduled task modifications related to user logon events."
        ],
        "enhancements": [
            "Enable process execution monitoring for boot and logon events.",
            "Implement application whitelisting to prevent unauthorized autostart entries.",
            "Restrict user permissions to modify registry autostart keys."
        ],
        "summary": "Document persistence attempts using boot or logon autostart execution methods.",
        "remediation": "Remove unauthorized registry entries, startup folder files, and scheduled tasks.",
        "improvements": "Enhance monitoring of system boot processes and user logon behaviors."
    }
