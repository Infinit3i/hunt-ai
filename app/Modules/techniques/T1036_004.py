def get_content():
    return {
        "id": "T1036.004",
        "url_id": "T1036/004",
        "title": "Masquerading: Masquerade Task or Service",
        "tactic": "Defense Evasion",
        "data_sources": "Process Creation Logs, File System Logs, Scheduled Task Logs, Endpoint Logs, Security Monitoring Tools",
        "protocol": "Scheduled Task Manipulation, Service Name Spoofing, Execution Path Obfuscation",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries disguising malicious tasks or services under legitimate names to evade detection and persist on systems.",
        "scope": "Identify suspicious scheduled tasks, system services, or daemon modifications that indicate an attempt to blend in with legitimate processes.",
        "threat_model": "Adversaries create or modify scheduled tasks, services, or daemons with deceptive names to execute malicious payloads while appearing as legitimate system components.",
        "hypothesis": [
            "Are there scheduled tasks or services with names similar to legitimate system processes?",
            "Are adversaries leveraging renamed system services to execute malicious payloads?",
            "Is there an increase in execution of tasks or services with anomalous parent-child process relationships?"
        ],
        "log_sources": [
            {"type": "Process Creation Logs", "source": "Sysmon (Event ID 1, 11), Windows Security Logs (Event ID 4688)"},
            {"type": "File System Logs", "source": "Windows Event Logs (Event ID 4663), Linux Auditd, macOS Unified Logs"},
            {"type": "Scheduled Task Logs", "source": "Windows Task Scheduler Logs (Event ID 106, 140), Linux cron logs"},
            {"type": "Endpoint Logs", "source": "EDR (CrowdStrike, Defender ATP, Carbon Black)"},
            {"type": "Security Monitoring Tools", "source": "SIEM, Host-based IDS Logs"}
        ],
        "detection_methods": [
            "Monitor for creation of scheduled tasks or services with names mimicking legitimate system processes.",
            "Detect execution of renamed tasks or services from unexpected locations.",
            "Identify persistence mechanisms leveraging system service masquerading."
        ],
        "spl_query": [
            "index=endpoint sourcetype=sysmon \n| search process_name IN (schtasks.exe, cron, systemctl) \n| where service_name IN (spoofed_services) \n| stats count by host, user, service_name, process_name"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify masquerading tasks or services and their execution locations.",
            "Analyze Process Creation Logs: Detect anomalies in service execution and task scheduling.",
            "Monitor for Unexpected Task or Service Execution: Identify services running from non-standard paths.",
            "Correlate with Threat Intelligence: Compare with known defense evasion techniques.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Masquerading Task/Service Detected: Block execution of disguised services and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for service and task masquerading techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1036.004 (Masquerade Task or Service)", "example": "Adversaries naming a scheduled task `Windows Update` to disguise malicious execution."},
            {"tactic": "Persistence", "technique": "T1543 (Create or Modify System Process)", "example": "Malware registering as a system service with a legitimate-looking name."}
        ],
        "watchlist": [
            "Flag execution of scheduled tasks or services with deceptive names.",
            "Monitor for anomalies in scheduled task execution paths.",
            "Detect unauthorized modifications to system services or cron jobs."
        ],
        "enhancements": [
            "Deploy service integrity monitoring to detect unauthorized service modifications.",
            "Implement behavioral analytics to detect abnormal scheduled task execution.",
            "Improve correlation between service masquerading activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious scheduled task or service-based defense evasion activity and affected systems.",
        "remediation": "Block execution of unauthorized services, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of service masquerading-based defense evasion techniques."
    }