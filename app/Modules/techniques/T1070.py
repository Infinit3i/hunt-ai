def get_content():
    return {
        "id": "T1070",
        "url_id": "T1070",
        "title": "Indicator Removal on Host",
        "tactic": "Defense Evasion",
        "data_sources": "File System Logs, Process Creation Logs, Endpoint Logs, Security Monitoring Tools",
        "protocol": "Local File Deletion, Event Log Modification, Custom Deletion Mechanisms",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries removing artifacts from hosts to erase forensic evidence and evade detection.",
        "scope": "Identify processes and user actions indicative of adversaries attempting to remove logs, delete files, or clear system traces.",
        "threat_model": "Adversaries delete event logs, modify files, and erase forensic traces to make detection and investigation more difficult.",
        "hypothesis": [
            "Are there unauthorized log deletions or modifications on hosts?",
            "Are adversaries leveraging built-in tools to clear forensic traces?",
            "Is there an increase in file deletions targeting security logs or evidence repositories?"
        ],
        "log_sources": [
            {"type": "File System Logs", "source": "Windows Security Event Logs (Event ID 1102, 104)"},
            {"type": "Process Creation Logs", "source": "Sysmon (Event ID 1, 5, 11), Linux Auditd"},
            {"type": "Endpoint Logs", "source": "EDR (CrowdStrike, Defender ATP, Carbon Black)"},
            {"type": "Security Monitoring Tools", "source": "SIEM, Antivirus Logs"}
        ],
        "detection_methods": [
            "Monitor for execution of known log clearing commands.",
            "Detect processes modifying or deleting security logs.",
            "Identify unauthorized file deletions targeting forensic data."
        ],
        "spl_query": [
            "index=endpoint sourcetype=sysmon \n| search event_id=1102 OR event_id=104 OR file_name=*evtx \n| stats count by host, user, process_name"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify log deletion and forensic tampering.",
            "Analyze Process Creation Logs: Detect anomalies in security log interactions.",
            "Monitor for Unauthorized File Deletions: Identify deletions of key forensic artifacts.",
            "Correlate with Threat Intelligence: Compare with known defense evasion techniques.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Indicator Removal Detected: Block unauthorized log deletion attempts and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for indicator removal techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1070 (Indicator Removal on Host)", "example": "Adversaries deleting security logs using PowerShell or built-in tools."},
            {"tactic": "Persistence", "technique": "T1547 (Boot or Logon Autostart Execution)", "example": "Malware maintaining persistence while hiding its traces."}
        ],
        "watchlist": [
            "Flag unexpected executions of log clearing commands.",
            "Monitor for anomalies in file deletion activities.",
            "Detect unauthorized modifications to security logs."
        ],
        "enhancements": [
            "Deploy file integrity monitoring to detect unauthorized modifications.",
            "Implement behavioral analytics to detect log tampering.",
            "Improve correlation between indicator removal activities and known threat actor techniques."
        ],
        "summary": "Document detected malicious indicator removal-based activity and affected systems.",
        "remediation": "Block unauthorized log modifications, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of indicator removal-based defense evasion techniques."
    }
