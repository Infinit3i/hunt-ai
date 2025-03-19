def get_content():
    return {
        "id": "T1485",
        "url_id": "T1485",
        "title": "Data Wiping Activity",
        "tactic": "Impact",
        "description": "Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability.",
        "tags": ["Data Destruction", "Impact"],
        "tactic": "Impact",
        "protocol": "",
        "os": "Windows, Linux, macOS, Containers, IaaS",
        "tips": [
            "Monitor execution and command-line parameters of binaries that could be involved in data destruction.",
            "Look for large quantities of file modifications in user directories and system folders.",
            "In cloud environments, detect anomalous high-volume deletion events."
        ],
        "data_sources": "Cloud Storage, Command, File, Image, Instance, Process, Snapshot, Volume",
        "log_sources": [
            {"type": "File System Activity", "source": "Sysmon (Event ID 23 - File Delete), Windows Security Logs"},
            {"type": "Process Execution", "source": "Sysmon (Event ID 1 - Process Creation, Event ID 13 - Registry Modification)"},
            {"type": "PowerShell & Script Execution", "source": "Windows Event ID 4104 (PowerShell Script Block Logging)"},
            {"type": "Endpoint Detection & Response (EDR)", "source": "CrowdStrike, Microsoft Defender, Carbon Black"}
        ],
        "detection_methods": [
            "Monitor for mass file deletions using file system logs.",
            "Detect the execution of known file-wiping commands or tools.",
            "Identify sudden changes in file system structures (e.g., entire folders disappearing).",
            "Track deletions of system logs or security records (e.g., Security Event Logs, forensic artifacts)."
        ],
        "spl_queries": [
            {
                "title": "Detect Mass File Deletion",
                "query": "index=filesystem EventCode=23 | stats count by FileName, ProcessName, ComputerName | where count > 100",
                "description": "Detects mass file deletions in a short time frame. Potential sign of data wiping malware or scripts."
            },
            {
                "title": "Detect Execution of File Wiping Commands",
                "query": "index=windows EventCode=1 | search CommandLine=\"*sdelete*\" OR CommandLine=\"*cipher /w*\" OR CommandLine=\"*rm -rf*\" | stats count by Account_Name, CommandLine, ComputerName",
                "description": "Detects execution of known file wiping commands. Identifies the user and system where the deletion occurred."
            },
            {
                "title": "Detect Log File Deletion",
                "query": "index=windows EventCode=23 | search FileName=\"C:\\Windows\\System32\\winevt\\Logs\\*.evtx\" | stats count by FileName, ProcessName, Account_Name",
                "description": "Tracks deletion of security logs or forensic records. Detects attempts to erase evidence before exfiltration."
            }
        ],
        "sigma_rules": [
            "Detect execution of sdelete, cipher, rm -rf, shred, wipe commands.",
            "Monitor PowerShell scripts that remove large numbers of files.",
            "Identify sudden spikes in file deletion events."
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify mass file deletions (Event ID 23). Detect execution of file-wiping commands. Monitor deletion of system logs or security artifacts.",
            "Correlate with Process Execution Logs: Identify which processes or scripts triggered deletions. Detect execution of PowerShell, Python, or batch scripts wiping data.",
            "Investigate Impacted Systems: Determine if critical files or security logs were deleted. Check if backup files or forensic artifacts were targeted.",
            "Monitor for Ransomware-Like Behavior: Identify if data wiping is part of a ransomware attack. Detect related file encryption or ransom note creation.",
            "Validate & Escalate: If malicious wiping is detected → Escalate to Incident Response. If false positive, adjust detection rules for legitimate cleanup activities."
        ],
        "expected_outcomes": [
            "Data Wiping Attack Detected: Stop the attack by isolating affected systems. Investigate impacted files and logs to assess damage. Restore lost data from backups if available.",
            "No Malicious Activity Found: Improve file deletion detection thresholds. Strengthen protection of critical logs and backups."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Attackers may attempt to delete security logs to erase traces of their activity."},
            {"tactic": "Impact", "technique": "T1486 (Data Encrypted for Impact)", "example": "Ransomware operators may encrypt files after deleting backups or security logs."},
            {"tactic": "Persistence", "technique": "T1543.003 (Create or Modify System Process)", "example": "Adversaries may establish a backdoor service after wiping forensic artifacts."},
            {"tactic": "Lateral Movement", "technique": "T1021.001 (Remote Desktop Protocol)", "example": "Attackers may use RDP for lateral movement before or after a wiping attack."},
            {"tactic": "Execution", "technique": "T1204.002 (User Execution - Malicious File)", "example": "Adversaries may execute additional scripts or binaries to maintain access."}
        ],
        "watchlist": [
            "Flag mass file deletions across multiple systems.",
            "Monitor execution of file deletion and wiping utilities.",
            "Detect ransomware-like behavior (e.g., encryption + deletion)."
        ],
        "enhancements": [
            "Restrict execution of file wiping utilities to administrators only.",
            "Enforce immutable backups to prevent ransomware wiping.",
            "Implement security logging protections to prevent log deletion."
        ],
        "summary": "Document data wiping attempts and affected systems.",
        "remediation": "Investigate the impact of data loss and attempt recovery. Harden systems against unauthorized file deletions. Implement stricter file integrity monitoring.",
        "improvements": "Develop behavioral detection models for file deletion anomalies. Automate containment responses for detected mass deletions."
    }
