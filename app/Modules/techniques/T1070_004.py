def get_content():
    return {
        "id": "T1070.004",
        "url_id": "T1070/004",
        "title": "Indicator Removal on Host: File Deletion",
        "tactic": "Defense Evasion",
        "data_sources": "File System Logs, Process Creation Logs, Endpoint Logs, Security Monitoring Tools",
        "protocol": "File Deletion Commands, Local Script Execution, Secure Deletion Mechanisms",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries deleting files to remove forensic evidence and evade detection.",
        "scope": "Identify suspicious file deletion activities that indicate an attempt to disrupt forensic investigations.",
        "threat_model": "Adversaries delete files using built-in utilities such as `del`, `rm`, `sdelete`, or `shred` to erase logs, artifacts, and evidence of malicious activity.",
        "hypothesis": [
            "Are there unauthorized file deletion operations targeting logs or forensic artifacts?",
            "Are adversaries leveraging command-line utilities to remove evidence?",
            "Is there an increase in file deletion attempts following suspicious activity?"
        ],
        "log_sources": [
            {"type": "File System Logs", "source": "Windows Security Event Logs (Event ID 4663), Linux Auditd"},
            {"type": "Process Creation Logs", "source": "Sysmon (Event ID 1, 5, 11), macOS Unified Logs"},
            {"type": "Endpoint Logs", "source": "EDR (CrowdStrike, Defender ATP, Carbon Black)"},
            {"type": "Security Monitoring Tools", "source": "SIEM, Host-based IDS Logs"}
        ],
        "detection_methods": [
            "Monitor for execution of known file deletion commands (`rm -rf`, `del /F /Q`, `sdelete.exe`, `shred -u`).",
            "Detect suspicious modifications or deletions of system files and security logs.",
            "Identify unauthorized process execution related to secure file deletion."
        ],
        "spl_query": [
            "index=endpoint sourcetype=sysmon \n| search command=*rm -rf* OR command=*del /F /Q* OR command=*sdelete* \n| stats count by host, user, command"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify unauthorized file deletion activities.",
            "Analyze Process Creation Logs: Detect anomalies in secure deletion behavior.",
            "Monitor for Unauthorized File Deletion: Identify use of `rm`, `sdelete`, or `shred` commands.",
            "Correlate with Threat Intelligence: Compare with known defense evasion techniques.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "File Deletion-Based Evasion Detected: Block unauthorized deletion attempts and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for file deletion-based defense evasion techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1070.004 (File Deletion)", "example": "Adversaries using `sdelete.exe` to securely delete forensic evidence."},
            {"tactic": "Persistence", "technique": "T1547 (Boot or Logon Autostart Execution)", "example": "Malware maintaining persistence while hiding its traces by deleting files."}
        ],
        "watchlist": [
            "Flag unexpected executions of file deletion commands.",
            "Monitor for anomalies in file deletion activities targeting logs and forensic artifacts.",
            "Detect unauthorized modifications or deletions of critical system files."
        ],
        "enhancements": [
            "Deploy file integrity monitoring to detect unauthorized deletions.",
            "Implement behavioral analytics to detect abnormal file deletion activities.",
            "Improve correlation between file deletion activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious file deletion-based defense evasion activity and affected systems.",
        "remediation": "Block unauthorized file deletion attempts, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of file deletion-based defense evasion techniques."
    }
