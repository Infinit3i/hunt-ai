def get_content():
    return {
        "id": "T1006",  # Tactic Technique ID
        "url_id": "1006",  # URL segment for technique reference
        "title": "Direct Volume Access",  # Name of the attack technique
        "description": "Adversaries may directly access a volume to bypass file access controls and file system monitoring. Programs with direct access can read and write files from the drive by parsing file system data structures, evading Windows file access controls and monitoring tools. Tools such as NinjaCopy in PowerSploit, as well as built-in utilities like vssadmin, wbadmin, and esentutl, can facilitate shadow copy or backup creation to evade common protections.",  # Simple description
        "tags": [
            "Direct Volume Access",
            "Logical Drive",
            "Shadow Copies",
            "NinjaCopy",
            "PowerSploit",
            "vssadmin",
            "wbadmin",
            "esentutl",
            "File System Monitoring Evasion",
            "Defense Evasion"
        ],  # Up to 10 tags
        "tactic": "Defense Evasion",  # Associated MITRE ATT&CK tactic
        "protocol": "N/A",  # Protocol used in the attack technique
        "os": "Network, Windows",  # Targeted operating systems
        "tips": [
            "Monitor handle opens on drive volumes made by processes to detect direct access",
            "Correlate process and command-line arguments with drive copying or shadow copy creation",
            "Enable and review PowerShell script logging to detect direct volume access attempts"
        ],
        "data_sources": "Command: Command Execution, Drive: Drive Access, File: File Creation",
        "log_sources": [
            {
                "type": "Command",
                "source": "Process Monitoring",
                "destination": "SIEM"
            },
            {
                "type": "Drive",
                "source": "Handle/Volume Auditing",
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
                "type": "Volume/Drive Handles",
                "location": "Logical volumes on Windows systems",
                "identify": "Direct read/write operations bypassing file access controls"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Shadow Copies/Backups",
                "location": "System volumes or backup destinations",
                "identify": "Copied data from volume snapshots or backups"
            }
        ],
        "detection_methods": [
            "Monitor processes that open handles to logical volumes in suspicious contexts",
            "Review command-line arguments for utilities like vssadmin, wbadmin, or esentutl used to create shadow copies",
            "Analyze PowerShell scripts for references to direct volume access functions or APIs"
        ],
        "apt": [],
        "spl_query": [],
        "hunt_steps": [
            "Identify processes enumerating or accessing raw drive volumes",
            "Correlate volume-level access with creation of shadow copies or backups",
            "Check for usage of specialized tools (e.g., NinjaCopy) in PowerShell logs"
        ],
        "expected_outcomes": [
            "Detection of attempts to bypass file access controls through raw volume access",
            "Identification of malicious shadow copy or backup creation used for data exfiltration or evasion",
            "Prevention of direct volume manipulation techniques that circumvent traditional monitoring"
        ],
        "false_positive": "Legitimate disk imaging or backup utilities may open volume handles. Validate context and user permissions to differentiate malicious behavior.",
        "clearing_steps": [
            "Terminate unauthorized processes accessing volumes directly",
            "Remove suspicious shadow copies or backups created outside normal procedures",
            "Review system and network shares to ensure no unauthorized backups remain"
        ],
        "mitre_mapping": [
            {
                "tactic": "Defense Evasion",
                "technique": "Direct Volume Access (T1006)",
                "example": "Using raw volume handles or shadow copy utilities to read/write data bypassing file system controls"
            }
        ],
        "watchlist": [
            "Unexpected usage of NinjaCopy, vssadmin, wbadmin, or esentutl for shadow copy creation",
            "Processes opening raw volume handles in non-backup contexts",
            "PowerShell scripts containing references to direct volume access functions"
        ],
        "enhancements": [
            "Deploy file integrity monitoring solutions that track volume-level read/write operations",
            "Enforce role-based access to backup and volume-level utilities",
            "Configure group policies or EDR to alert on raw disk handle access attempts"
        ],
        "summary": "Adversaries may access a drive's logical volumes directly to bypass file system monitoring and controls, often creating shadow copies or backups with utilities like vssadmin or wbadmin to evade defenses and potentially exfiltrate data.",
        "remediation": "Restrict direct volume access to only authorized processes or backup utilities, monitor for suspicious usage of shadow copy tools, and maintain robust logging for PowerShell and volume handle operations.",
        "improvements": "Enhance monitoring of low-level disk operations, integrate volume access logs into SIEM, and train security teams on identifying direct volume manipulation techniques."
    }
