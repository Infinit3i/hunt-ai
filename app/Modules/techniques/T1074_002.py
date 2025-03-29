def get_content():
    return {
        "id": "T1074.002",  # Tactic Technique ID
        "url_id": "T1074/002",  # URL segment for technique reference
        "title": "Data Staged: Remote Data Staging",  # Name of the attack technique
        "description": "Adversaries may stage data collected from multiple systems on a single host before exfiltration, potentially using compression or encryption tools. By consolidating data in a remote location or cloud instance, adversaries can reduce connections to C2 and evade detection.",  # Simple description
        "tags": [
            "Data Staging",
            "Remote Data Staging",
            "Cloud",
            "Collection",
            "Mandiant M-Trends 2020",
            "PWC Cloud Hopper April 2017",
            "FIN6",
            "APT40",
            "MoustachedBouncer",
            "FunnyDream Campaign"
        ],  # Up to 10 tags
        "tactic": "Collection",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "IaaS, Linux, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Monitor processes that read files from disparate sources and write them to a single directory or file",
            "Audit publicly writable directories and staging locations (e.g., temp, recycle bin) for archives or encrypted data",
            "Check cloud instances or VMs for unexpected data storage and transfers"
        ],
        "data_sources": "Command: Command Execution, File: File Access, File: File Creation",
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
            }
        ],
        "source_artifacts": [
            {
                "type": "File",
                "location": "Various systems or file shares",
                "identify": "Collected data from multiple hosts"
            }
        ],
        "destination_artifacts": [
            {
                "type": "File",
                "location": "Central staging location on a single system or cloud instance",
                "identify": "Aggregated or compressed data ready for exfiltration"
            }
        ],
        "detection_methods": [
            "File integrity monitoring for newly created archives or suspicious file modifications",
            "Process command-line analysis for bulk file copying or compression utilities",
            "Monitoring of cloud environments for new instance creation and unexpected data storage"
        ],
        "apt": [
            "APT40",
            "FIN6",
            "FIN8",
            "MoustachedBouncer",
            "Cicada"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Identify new or large archive files on staging hosts or cloud instances",
            "Correlate file access logs across multiple endpoints to a single staging location",
            "Review network traffic for significant data flows from multiple hosts to a single system"
        ],
        "expected_outcomes": [
            "Discovery of remote staging directories containing data from multiple systems",
            "Identification of tools or processes used to combine and encrypt data prior to exfiltration",
            "Detection of cloud resources or on-premise hosts acting as staging points"
        ],
        "false_positive": "Legitimate bulk data collection or backups may produce similar behavior. Validate against authorized tasks and maintenance windows.",
        "clearing_steps": [
            "Delete or quarantine staged archives and compression tools",
            "Revoke access to compromised cloud instances or staging hosts",
            "Revert unauthorized changes to system configurations or file shares"
        ],
        "mitre_mapping": [
            {
                "tactic": "Exfiltration",
                "technique": "Archive Collected Data (T1560)",
                "example": "Combining and compressing data from multiple hosts before exfiltration"
            }
        ],
        "watchlist": [
            "Unexpected file operations on central file shares or staging directories",
            "Spikes in network traffic from many hosts to a single internal IP or cloud instance",
            "Unusual or newly created archives containing large volumes of data"
        ],
        "enhancements": [
            "Use endpoint and network detection solutions to correlate file operations across multiple systems",
            "Implement role-based access controls to limit who can read/write large data sets",
            "Enable logging and alerting on new VM or container creation in cloud environments"
        ],
        "summary": "Remote data staging consolidates data from multiple sources onto one system or cloud instance, minimizing outward connections and helping adversaries evade detection prior to exfiltration.",
        "remediation": "Monitor, restrict, and log data transfers to potential staging locations. Employ anomaly detection for sudden data spikes, and enforce least privilege to limit unauthorized data aggregation.",
        "improvements": "Correlate endpoint, network, and cloud logs to identify unusual cross-system data transfers. Deploy robust file integrity and process monitoring to quickly detect mass data staging activities."
    }
