def get_content():
    return {
        "id": "T1092",
        "url_id": "T1092",
        "title": "Communication Through Removable Media",
        "tactic": "Command and Control",
        "data_sources": "File System Logs, Removable Media Logs, Endpoint Logs, Intrusion Detection Systems (IDS)",
        "protocol": "USB, SD Card, External Hard Drive, Custom Offline Transfer Mechanisms",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Monitor file reads/writes on removable media for unexpected behavior.",
            "Restrict or disable auto-run and auto-play features to limit malicious execution.",
            "Use device control software to block or alert on unauthorized USB or other removable drives.",
            "Regularly scan removable media for malware before connecting to critical systems."
        ],
        "data_sources": "Drive, File, Process",
        "log_sources": [
            {"type": "File System Logs", "source": "Windows Security Event Logs (Event ID 4663, 4660)"},
            {"type": "Removable Media Logs", "source": "USB Device Logs, Device Control Logs"},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 1, 3, 6, 11), EDR (CrowdStrike, Defender ATP)"},
            {"type": "IDS", "source": "Host-based Intrusion Detection Systems (HIDS)"}
        ],
        "detection_methods": [
            "Monitor for execution of files stored on removable media.",
            "Detect unauthorized USB devices being connected to critical systems.",
            "Identify unexpected modifications to files on removable drives."
        ],
        "apt": [
            "APT28"
        ],
        "spl_query": [
            "index=endpoint sourcetype=sysmon \n| search event_id=6 OR event_id=11 \n| stats count by host, file_path"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify suspicious removable media-related activity.",
            "Analyze USB Device Logs: Detect anomalies in removable media usage.",
            "Monitor for Unusual File Execution: Identify unauthorized script executions from external storage.",
            "Correlate with Threat Intelligence: Compare with known C2 techniques leveraging removable media.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Removable Media-Based C2 Detected: Block unauthorized removable media access and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for removable media-based C2 techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1092 (Communication Through Removable Media)", "example": "C2 instructions transferred via USB drives."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data exfiltrated using removable storage devices."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs after executing from removable media."}
        ],
        "watchlist": [
            "Flag unauthorized removable media devices connecting to critical systems.",
            "Monitor for anomalies in removable media file execution patterns.",
            "Detect unauthorized use of external storage devices for C2."
        ],
        "enhancements": [
            "Deploy device control solutions to restrict removable media usage.",
            "Implement behavioral analytics to detect abnormal removable media activity.",
            "Improve correlation between removable media activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious removable media-based command-and-control activity and affected systems.",
        "remediation": "Block unauthorized removable media access, revoke compromised credentials, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of removable media-based command-and-control techniques."
    }
