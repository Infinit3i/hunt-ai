def get_content():
    return {
        "id": "T1070.006",
        "url_id": "T1070/006",
        "title": "Indicator Removal on Host: Timestomp",
        "tactic": "Defense Evasion",
        "data_sources": "File System Logs, Process Creation Logs, Endpoint Logs, Security Monitoring Tools",
        "protocol": "File Attribute Modification, Timestamp Alteration, Anti-Forensic Techniques",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries modifying file timestamps to avoid forensic detection and mislead investigators.",
        "scope": "Identify suspicious file timestamp alterations that indicate an attempt to disguise malicious activity.",
        "threat_model": "Adversaries alter timestamps of files, such as access, creation, or modification times, using built-in utilities or specialized tools like `timestomp.exe`, `touch`, or `SetFile` to evade forensic analysis.",
        "hypothesis": [
            "Are there unauthorized modifications to file timestamps?",
            "Are adversaries leveraging built-in utilities to manipulate file attributes?",
            "Is there an increase in backdated or altered timestamps following suspicious activity?"
        ],
        "log_sources": [
            {"type": "File System Logs", "source": "Windows Security Event Logs (Event ID 4663), Linux Auditd, macOS Unified Logs"},
            {"type": "Process Creation Logs", "source": "Sysmon (Event ID 1, 11), Windows Security Logs"},
            {"type": "Endpoint Logs", "source": "EDR (CrowdStrike, Defender ATP, Carbon Black)"},
            {"type": "Security Monitoring Tools", "source": "SIEM, Host-based IDS Logs"}
        ],
        "detection_methods": [
            "Monitor for execution of known timestamp manipulation commands (`timestomp.exe`, `touch`, `SetFile -d`).",
            "Detect unauthorized modifications to file attributes.",
            "Identify files with timestamps inconsistent with known system events."
        ],
        "spl_query": [
            "index=endpoint sourcetype=sysmon \n| search command=*timestomp* OR command=*touch* OR command=*SetFile* \n| stats count by host, user, command"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify unauthorized timestamp modifications.",
            "Analyze Process Creation Logs: Detect anomalies in file attribute changes.",
            "Monitor for Backdated Files: Identify inconsistencies between timestamps and system events.",
            "Correlate with Threat Intelligence: Compare with known defense evasion techniques.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Timestomping Detected: Block unauthorized file attribute changes and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for timestamp modification-based defense evasion techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1070.006 (Timestomp)", "example": "Adversaries using `timestomp.exe` to alter timestamps of malicious files."},
            {"tactic": "Persistence", "technique": "T1547 (Boot or Logon Autostart Execution)", "example": "Malware maintaining persistence while hiding its traces by modifying file timestamps."}
        ],
        "watchlist": [
            "Flag unexpected executions of timestamp manipulation commands.",
            "Monitor for anomalies in file attribute modification activities.",
            "Detect unauthorized alterations of file metadata in system directories."
        ],
        "enhancements": [
            "Deploy file integrity monitoring to detect unauthorized changes.",
            "Implement behavioral analytics to detect abnormal file timestamp modifications.",
            "Improve correlation between timestomping activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious timestomping-based defense evasion activity and affected systems.",
        "remediation": "Block unauthorized timestamp modifications, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of timestamp modification-based defense evasion techniques."
    }
