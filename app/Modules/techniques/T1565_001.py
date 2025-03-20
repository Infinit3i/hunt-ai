def get_content():
    return {
        "id": "T1565.001",  # Tactic Technique ID
        "url_id": "1565/001",  # URL segment for technique reference
        "title": "Data Manipulation: Stored Data Manipulation",  # Name of the attack technique
        "description": "Adversaries may insert, delete, or manipulate data at rest in order to influence external outcomes or hide activity, thus threatening the integrity of the data. By manipulating stored data, adversaries may attempt to affect a business process, organizational understanding, and decision making. Stored data could include various file formats, such as Office files, databases, stored emails, and custom file formats. The type of modification and impact depends on the data and the adversary’s objectives, potentially requiring specialized expertise and prolonged information gathering.",  # Simple description
        "tags": [
            "Data Manipulation",
            "Stored Data Manipulation",
            "Integrity",
            "File Modification",
            "FireEye APT38 Oct 2018",
            "DOJ Lazarus Sony 2018",
            "Unit42 Agrius 2023",
            "CrowdStrike SUNSPOT Implant January 2021",
            "Ready.gov IT DRP",
            "Impact"
        ],
        "tactic": "Impact",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "Linux, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Inspect file hashes, locations, and modifications for suspicious changes",
            "Use file integrity monitoring on critical directories or databases",
            "Restrict write permissions to essential data repositories"
        ],
        "data_sources": "File: File Creation, File: File Deletion, File: File Modification",
        "log_sources": [
            {
                "type": "File",
                "source": "File System Auditing",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "File",
                "location": "Local/Shared Storage or Database",
                "identify": "Modified or Deleted Files"
            }
        ],
        "destination_artifacts": [
            {
                "type": "File",
                "location": "Target Directories/Databases",
                "identify": "Altered Data"
            }
        ],
        "detection_methods": [
            "File integrity monitoring to detect unauthorized modifications",
            "Monitoring for unexpected file creation/deletion in sensitive locations",
            "Regular hashing of critical files to identify tampering"
        ],
        "apt": [
            "APT38",
            "Lazarus",
            "Agrius"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Review logs for unexplained file modifications/deletions in key directories",
            "Correlate file system changes with user or process behavior",
            "Check for anomalies in databases or other structured data repositories"
        ],
        "expected_outcomes": [
            "Identification of unauthorized or suspicious data modifications",
            "Detection of missing or altered files",
            "Discovery of processes or users responsible for data tampering"
        ],
        "false_positive": "Legitimate maintenance, patching, or data migration processes may cause similar file activity. Validate changes against authorized updates.",
        "clearing_steps": [
            "Restore affected files or databases from secure backups",
            "Revert unauthorized changes in version-controlled repositories",
            "Audit and tighten access controls to prevent further tampering"
        ],
        "mitre_mapping": [
            {
                "tactic": "Impact",
                "technique": "Data Manipulation (T1565)",
                "example": "Altering stored data to disrupt operations or conceal malicious activity"
            }
        ],
        "watchlist": [
            "Sudden large-scale modifications to critical files or databases",
            "Frequent file deletions without corresponding business justification",
            "Unusual user or process access patterns in sensitive locations"
        ],
        "enhancements": [
            "Enable real-time alerts on file integrity monitoring systems",
            "Implement database-level change tracking and auditing"
        ],
        "summary": "Stored data manipulation can undermine the integrity of critical information, potentially affecting business processes, organizational understanding, and decision-making.",
        "remediation": "Maintain strong file integrity monitoring, implement least privilege for data access, and regularly back up and verify critical data.",
        "improvements": "Strengthen logging and auditing for key data repositories, enforce strict access controls, and perform routine data integrity checks to quickly detect and address unauthorized modifications."
    }
