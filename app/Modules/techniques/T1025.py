def get_content():
    return {
        "id": "T1025",  # Tactic Technique ID
        "url_id": "1025",  # URL segment for technique reference
        "title": "Data from Removable Media",  # Name of the attack technique
        "description": "Adversaries may search removable media (e.g., USB drives, optical disks) connected to a compromised system for sensitive files prior to exfiltration, using built-in commands or scripts to collect data.",  # Simple description
        "tags": [
            "Data from Removable Media",
            "Removable Media",
            "Collection",
            "cmd",
            "PowerShell",
            "WMI",
            "USBStealer",
            "Machete",
            "InvisiMole",
            "Transparent Tribe"
        ],  # Up to 10 tags
        "tactic": "Collection",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "Linux, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Monitor process execution and command-line arguments for removable media file collection",
            "Alert on large-scale file copying or unusual processes accessing removable drives",
            "Audit usage of built-in OS tools (e.g., PowerShell, WMI) to gather data from USB or optical media"
        ],
        "data_sources": "Command: Command Execution, File: File Access",
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
                "type": "Files on Removable Media",
                "location": "USB drives, optical discs, or other removable storage",
                "identify": "Sensitive documents, configurations, or other data"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Staged Data",
                "location": "Local directories or staging folders",
                "identify": "Copied files from removable media"
            }
        ],
        "detection_methods": [
            "Correlate file access events on removable media with suspicious process execution",
            "Look for newly created archives or large file transfers from removable drives",
            "Analyze command-line arguments for enumeration or copying of removable media content"
        ],
        "apt": [
            "Sednit (USBStealer)",
            "Transparent Tribe",
            "Machete"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Identify processes enumerating or accessing files on removable media",
            "Check for newly created or modified archives that may contain exfiltrated data",
            "Correlate removable media access times with suspicious user logins or off-hours usage"
        ],
        "expected_outcomes": [
            "Detection of adversary-driven data collection from USB or optical disks",
            "Identification of compromised accounts or processes harvesting data from removable media",
            "Prevention of sensitive data exfiltration via removable devices"
        ],
        "false_positive": "Legitimate file transfers or backups may involve copying data from removable media. Validate context and authorized usage patterns.",
        "clearing_steps": [
            "Terminate unauthorized processes interacting with removable media",
            "Remove or disconnect any suspicious removable devices",
            "Review and tighten policies for removable media usage and file transfers"
        ],
        "mitre_mapping": [
            {
                "tactic": "Collection",
                "technique": "Data from Removable Media (T1025)",
                "example": "Using built-in commands or scripts to search and copy files from USB drives"
            }
        ],
        "watchlist": [
            "Processes accessing large numbers of files on removable drives in a short time",
            "Off-hours or unexpected usage of removable media by privileged accounts",
            "Unusual process command-line parameters referencing removable media paths"
        ],
        "enhancements": [
            "Implement DLP solutions to detect and block unauthorized copying from removable drives",
            "Use endpoint detection and response (EDR) tools to track file operations on removable media",
            "Enforce policies restricting removable media usage to authorized personnel"
        ],
        "summary": "Removable media can hold sensitive data that adversaries may target for collection prior to exfiltration, leveraging built-in OS commands or scripts to copy files from USB or optical drives.",
        "remediation": "Restrict removable media usage through policy, monitor for unusual file access or transfer patterns, and investigate suspicious processes accessing removable drives.",
        "improvements": "Enable file integrity monitoring for removable media, enforce strong authentication for privileged users, and regularly audit removable media logs to detect unauthorized usage."
    }
