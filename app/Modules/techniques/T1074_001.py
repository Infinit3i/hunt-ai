def get_content():
    return {
        "id": "T1074.001",  # Tactic Technique ID
        "url_id": "T1074/001",  # URL segment for technique reference
        "title": "Data Staged: Local Data Staging",  # Name of the attack technique
        "description": "Adversaries may stage collected data in a central location on the local system prior to exfiltration, potentially combining files or storing them in locations like the Windows Registry or local databases.",  # Simple description
        "tags": [
            "Data Staging",
            "Local Data Staging",
            "Collection",
            "Windows Registry",
            "cmd",
            "bash",
            "Archive Collected Data",
            "Prevailion DarkWatchman 2021",
            "FireEye TRITON 2019",
            "Securelist Dtrack"
        ],  # Up to 10 tags
        "tactic": "Collection",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "Linux, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Monitor publicly writable directories (temp, recycle bin) for compressed/encrypted files",
            "Inspect processes and command-line usage for bulk file copying or archiving",
            "Check local storage repositories (e.g., Windows Registry) for unusual data writes"
        ],
        "data_sources": "Command: Command Execution, File: File Access, File: File Creation, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {
                "type": "Command",
                "source": "Process Monitoring",
                "destination": "SIEM"
            },
            {
                "type": "File",
                "source": "File System Auditing",
                "destination": "SIEM"
            },
            {
                "type": "Windows Registry",
                "source": "Registry Auditing",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "File",
                "location": "Local directories, databases, or registry",
                "identify": "Data staged prior to exfiltration"
            }
        ],
        "destination_artifacts": [
            {
                "type": "File",
                "location": "Central/local staging folders",
                "identify": "Aggregated or archived data"
            }
        ],
        "detection_methods": [
            "File integrity monitoring to detect new archives or unusual file activity",
            "Process command-line analysis for file copying, compression, or encryption",
            "Registry auditing for unexpected writes in suspicious keys/paths"
        ],
        "apt": [
            "Turla",
            "Gamaredon",
            "Sofacy",
            "FIN6",
            "Kimsuky"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Identify newly created archives in local directories (e.g., temp, recycle bin)",
            "Correlate file access events with suspicious processes or accounts",
            "Review registry modifications for data that could be used for staging"
        ],
        "expected_outcomes": [
            "Detection of local data staging directories or archives",
            "Identification of processes or tools used to combine or encrypt files",
            "Discovery of malicious use of the Windows Registry for data storage"
        ],
        "false_positive": "Legitimate data backups, system maintenance, or authorized archiving may produce similar file activity. Validate against approved processes.",
        "clearing_steps": [
            "Remove or quarantine staged archives and associated utilities",
            "Restore any altered registry keys from backups",
            "Review and tighten file and registry access permissions"
        ],
        "mitre_mapping": [
            {
                "tactic": "Collection",
                "technique": "Archive Collected Data (T1560)",
                "example": "Combining and compressing files locally before exfiltration"
            }
        ],
        "watchlist": [
            "Publicly writable folders with sudden large archive files",
            "Processes accessing files from disparate locations and writing to a single directory",
            "Suspicious or frequent writes to the Windows Registry"
        ],
        "enhancements": [
            "Use endpoint detection and response (EDR) to track file operations in real-time",
            "Implement least privilege for user and process accounts to restrict unauthorized data collection"
        ],
        "summary": "Local data staging involves collecting and potentially archiving data on a single host prior to exfiltration, often leveraging known utilities and directories.",
        "remediation": "Monitor and restrict write access to common staging directories, use file integrity checks, and audit the Windows Registry for suspicious activity.",
        "improvements": "Refine detection rules to identify bulk file operations, correlate process and file logs for anomalies, and regularly test restoration processes from backups."
    }
