def get_content():
    return {
        "id": "T1039",  # Tactic Technique ID
        "url_id": "1039",  # URL segment for technique reference
        "title": "Data from Network Shared Drive",  # Name of the attack technique
        "description": "Adversaries may search network shares to collect files of interest prior to exfiltration. This can be done using built-in commands or scripts that traverse remote directories, such as cmd, WMI, or PowerShell.",  # Simple description
        "tags": [
            "Data from Network Shared Drive",
            "Network Share",
            "Collection",
            "cmd",
            "PowerShell",
            "WMI",
            "DFIR Conti Bazar",
            "ESET Ramsay",
            "Forcepoint Monsoon",
            "NHS Digital Egregor"
        ],  # Up to 10 tags
        "tactic": "Collection",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "Linux, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Monitor for suspicious file accesses on network shares",
            "Audit privileged user behavior and large-scale file copying",
            "Check for unexpected use of built-in commands (cmd, WMI, PowerShell) to traverse remote directories"
        ],
        "data_sources": "Command: Command Execution, File: File Access, Network Share: Network Share Access, Network Traffic: Network Connection Creation, Network Traffic: Network Traffic Content, Network Traffic: Network Traffic Flow",
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
                "type": "Network Share",
                "source": "Share Access Logs",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Files on Network Shares",
                "location": "Remote shared directories",
                "identify": "Documents, configurations, or other sensitive data"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Staged Data",
                "location": "Local or temporary directories on compromised system",
                "identify": "Copied files from network shares"
            }
        ],
        "detection_methods": [
            "Correlate file access events on network shares with suspicious process execution",
            "Analyze command-line arguments for directory traversal or mass file copying",
            "Review network traffic for unexpected connections to file servers"
        ],
        "apt": [
            "BRONZE BUTLER",
            "Gamaredon",
            "Sowbug"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Identify abnormal file read or copy operations from network shares",
            "Check for newly created archives or large data transfers",
            "Correlate suspicious share access with user login times and endpoints"
        ],
        "expected_outcomes": [
            "Detection of unauthorized or excessive data collection from network shares",
            "Identification of compromised accounts or processes accessing sensitive directories",
            "Prevention of large-scale exfiltration via remote file servers"
        ],
        "false_positive": "Legitimate file shares for backups or business processes may show similar behavior. Validate context and authorized usage patterns.",
        "clearing_steps": [
            "Terminate processes or sessions responsible for unauthorized share access",
            "Restrict or revoke compromised credentials",
            "Audit and tighten permissions on network shares to enforce least privilege"
        ],
        "mitre_mapping": [
            {
                "tactic": "Collection",
                "technique": "Data from Network Shared Drive (T1039)",
                "example": "Using cmd or PowerShell to traverse and copy files from network shares"
            }
        ],
        "watchlist": [
            "Processes repeatedly accessing numerous files on network shares",
            "Spikes in read or copy operations from sensitive directories",
            "Unusual or unauthorized share connections from non-standard endpoints"
        ],
        "enhancements": [
            "Implement file integrity monitoring for shared directories",
            "Deploy EDR solutions to track file access patterns over network shares",
            "Use network segmentation to limit share access from untrusted hosts"
        ],
        "summary": "Network shared drives often contain critical data that adversaries can search and collect prior to exfiltration, leveraging built-in commands or scripts to access and copy files remotely.",
        "remediation": "Restrict share permissions to only necessary accounts, monitor share access logs, and detect anomalous processes interacting with remote directories.",
        "improvements": "Regularly audit network share permissions, enforce strong authentication and SMB signing, and deploy behavioral analytics to detect unusual share access patterns."
    }
