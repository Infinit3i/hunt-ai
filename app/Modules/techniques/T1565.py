def get_content():
    return {
        "id": "T1565",  # Tactic Technique ID
        "url_id": "1565",  # URL segment for technique reference
        "title": "Data Manipulation",  # Name of the attack technique
        "description": "Adversaries may insert, delete, or manipulate data to threaten data integrity, influence outcomes, or hide activity. For complex systems, specialized expertise and prolonged information gathering may be required.",  # One pair of quotes for the description
        "tags": [
            "Data Manipulation",
            "Integrity",
            "File Modification",
            "Network Traffic",
            "Impact",
            "Elephant Beetle",
            "Sygnia Elephant Beetle Jan 2022",
            "Ready.gov IT DRP"
        ],  # Up to 10 tags
        "tactic": "Impact",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "Linux, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Inspect important file hashes, locations, and modifications for unexpected changes",
            "Perform manual or out-of-band integrity checks for critical processes and data transmissions",
            "Implement file integrity monitoring and version control to detect unauthorized changes"
        ],
        "data_sources": "File, Network Traffic, Process",  # Relevant data sources
        "log_sources": [
            {"type": "File", "source": "File Integrity Monitoring", "destination": "SIEM"},
            {"type": "Network Traffic", "source": "Network Monitoring", "destination": "SIEM"},
            {"type": "Process", "source": "Endpoint Monitoring", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {
                "type": "File",
                "location": "Local or shared storage",
                "identify": "Modified or deleted files"
            }
        ],
        "destination_artifacts": [
            {
                "type": "File",
                "location": "Target system or database",
                "identify": "Altered data records or logs"
            }
        ],
        "detection_methods": [
            "File integrity monitoring and change detection on critical data repositories",
            "Network traffic analysis for unusual or out-of-spec data manipulation",
            "Process auditing for unexpected file or database operations"
        ],
        "apt": [
            "Elephant Beetle"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Review logs for unexplained file modifications/deletions",
            "Check for anomalies in database or application data fields",
            "Correlate user access patterns with data manipulation events"
        ],
        "expected_outcomes": [
            "Identification of unauthorized data modifications",
            "Discovery of missing or altered records/logs",
            "Detection of suspicious processes or scripts responsible for data tampering"
        ],
        "false_positive": "Authorized maintenance, patching, or data migrations may appear as data manipulation. Validate business context and change windows.",
        "clearing_steps": [
            "Restore manipulated data from secure backups",
            "Revert unauthorized changes in version-controlled repositories",
            "Audit account permissions and revoke unnecessary privileges"
        ],
        "mitre_mapping": [
            {
                "tactic": "Impact",
                "technique": "Defacement (T1491)",
                "example": "Adversaries may alter web pages or internal data to mislead or disrupt operations"
            }
        ],
        "watchlist": [
            "Unexpected changes to critical system files or configurations",
            "Large-scale database updates outside of normal operational hours",
            "Gaps or inconsistencies in application or transaction logs"
        ],
        "enhancements": [
            "Enable rigorous change management and version control systems",
            "Implement multi-factor authentication for administrative access to sensitive data"
        ],
        "summary": "Data manipulation threatens the integrity of critical information by inserting, deleting, or altering records, potentially influencing outcomes or masking malicious activity.",
        "remediation": "Use file integrity monitoring, robust backups, version control, and strict access controls to detect and revert unauthorized changes.",
        "improvements": "Strengthen real-time monitoring of data repositories, implement strict logging and auditing policies, and regularly validate data integrity through automated checks."
    }
