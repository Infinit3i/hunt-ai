def get_content():
    return {
        "id": "T1036",
        "url_id": "T1036",
        "title": "Masquerading",
        "tactic": "Defense Evasion",
        "data_sources": "Process Creation Logs, File System Logs, Endpoint Logs, Security Monitoring Tools",
        "protocol": "Process Name Manipulation, File Renaming, System Path Abuse",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries disguising their malicious activities by modifying names, file locations, or system artifacts to blend in with legitimate system processes.",
        "scope": "Identify suspicious process executions and file modifications that indicate an attempt to hide malicious behavior.",
        "threat_model": "Adversaries rename files, modify process names, or change execution paths to mimic legitimate applications, tricking defenders into overlooking their presence.",
        "hypothesis": [
            "Are there unauthorized processes running with names resembling system files?",
            "Are adversaries leveraging renamed binaries to execute malicious payloads?",
            "Is there an increase in file name or execution path modifications following suspicious activity?"
        ],
        "log_sources": [
            {"type": "Process Creation Logs", "source": "Sysmon (Event ID 1, 11), Windows Security Logs (Event ID 4688)"},
            {"type": "File System Logs", "source": "Windows Security Event Logs (Event ID 4663), Linux Auditd, macOS Unified Logs"},
            {"type": "Endpoint Logs", "source": "EDR (CrowdStrike, Defender ATP, Carbon Black)"},
            {"type": "Security Monitoring Tools", "source": "SIEM, Host-based IDS Logs"}
        ],
        "detection_methods": [
            "Monitor for processes running from unusual paths or renamed system executables.",
            "Detect file name changes resembling common system files.",
            "Identify execution of binaries from uncommon locations or user directories."
        ],
        "spl_query": [
            "index=endpoint sourcetype=sysmon \n| search process_name=*svchost* OR process_name=*lsass* OR process_name=*explorer* \n| where parent_process!=expected_parent \n| stats count by host, user, process_name, parent_process"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify execution of renamed or masqueraded processes.",
            "Analyze Process Creation Logs: Detect anomalies in parent-child process relationships.",
            "Monitor for Unexpected Binary Execution: Identify processes running from user or temp directories.",
            "Correlate with Threat Intelligence: Compare with known defense evasion techniques.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Masquerading Detected: Block execution of renamed malicious processes and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for masquerading-based defense evasion techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1036 (Masquerading)", "example": "Adversaries renaming `malware.exe` to `svchost.exe` to avoid detection."},
            {"tactic": "Persistence", "technique": "T1547 (Boot or Logon Autostart Execution)", "example": "Malware persisting under a legitimate process name."}
        ],
        "watchlist": [
            "Flag executions of system-named binaries from unexpected locations.",
            "Monitor for anomalies in process parent-child relationships.",
            "Detect unauthorized renaming of executables within system directories."
        ],
        "enhancements": [
            "Deploy process integrity monitoring to detect renamed system processes.",
            "Implement behavioral analytics to detect abnormal process execution.",
            "Improve correlation between masquerading activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious masquerading-based defense evasion activity and affected systems.",
        "remediation": "Block execution of unauthorized renamed binaries, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of masquerading-based defense evasion techniques."
    }
