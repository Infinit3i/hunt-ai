def get_content():
    return {
        "id": "T1547.009",
        "url_id": "T1547/009",
        "title": "Persistence: Shortcut Modification",
        "tactic": "Persistence",
        "data_sources": "File System Logs, Process Creation Logs, Endpoint Logs, Security Monitoring Tools",
        "protocol": "Windows Shell Shortcuts, LNK Files, Desktop Configuration",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries modifying shortcut files (.lnk, .desktop) to establish persistence and execute malicious payloads.",
        "scope": "Identify suspicious modifications to shortcut files and unexpected process executions initiated via shortcuts.",
        "threat_model": "Adversaries modify shortcut files to execute malicious payloads under the guise of legitimate applications. This allows persistence while blending into normal user activity.",
        "hypothesis": [
            "Are there unauthorized modifications to user or system shortcut files?",
            "Are adversaries leveraging shortcuts to execute malicious payloads?",
            "Is there an increase in processes executed via shortcuts in unexpected locations?"
        ],
        "log_sources": [
            {"type": "File System Logs", "source": "Windows Event Logs (Event ID 4663), Linux Auditd, macOS Unified Logs"},
            {"type": "Process Creation Logs", "source": "Sysmon (Event ID 1, 11), Windows Security Logs (Event ID 4688)"},
            {"type": "Endpoint Logs", "source": "EDR (CrowdStrike, Defender ATP, Carbon Black)"},
            {"type": "Security Monitoring Tools", "source": "SIEM, Host-based IDS Logs"}
        ],
        "detection_methods": [
            "Monitor for creation or modification of shortcut files in sensitive locations.",
            "Detect processes launched via shortcut files executing unexpected payloads.",
            "Identify shortcut files pointing to suspicious or non-standard locations."
        ],
        "spl_query": [
            "index=endpoint sourcetype=sysmon \n| search file_name=*.lnk OR file_name=*.desktop \n| where process_path NOT IN (expected_paths) \n| stats count by host, user, file_name, process_path"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify execution of suspicious shortcut-based processes.",
            "Analyze Process Creation Logs: Detect anomalies in shortcut-launched processes.",
            "Monitor for Unexpected Shortcut Modifications: Identify shortcut files pointing to non-standard executables.",
            "Correlate with Threat Intelligence: Compare with known persistence techniques.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Shortcut-Based Persistence Detected: Block execution of malicious shortcut files and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for shortcut modification-based persistence techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1547.009 (Shortcut Modification)", "example": "Adversaries modifying `Startup` folder shortcuts to execute malware."},
            {"tactic": "Defense Evasion", "technique": "T1036 (Masquerading)", "example": "Malware disguising itself as a legitimate application via shortcut modification."}
        ],
        "watchlist": [
            "Flag modifications to shortcuts in startup or commonly used directories.",
            "Monitor for anomalies in shortcut-based process executions.",
            "Detect unauthorized creation of shortcut files with malicious payloads."
        ],
        "enhancements": [
            "Deploy file integrity monitoring to detect unauthorized shortcut modifications.",
            "Implement behavioral analytics to detect abnormal shortcut-based process execution.",
            "Improve correlation between shortcut modification activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious shortcut modification-based persistence activity and affected systems.",
        "remediation": "Block execution of unauthorized shortcut modifications, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of shortcut modification-based persistence techniques."
    }
