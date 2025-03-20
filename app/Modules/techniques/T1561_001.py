def get_content():
    return {
        "id": "T1561.001",  # Tactic Technique ID
        "url_id": "1561/001",  # URL segment for technique reference
        "title": "Disk Wipe: Disk Content Wipe",  # Name of the attack technique
        "description": "Adversaries may overwrite or corrupt raw disk content (including partial or entire disk sectors) to disrupt availability on specific systems or across a network. This destructive behavior often relies on direct disk access via tools or drivers (e.g., RawDisk) and may propagate via worm-like features using stolen credentials, admin shares, or other intrusion techniques.",  # Simple description
        "tags": [
            "Disk Content Wipe",
            "RawDisk",
            "Novetta Blockbuster",
            "Hermetic Wiper",
            "BlackCat",
            "AcidRain JAGS 2022",
            "Crowdstrike WhisperGate January 2022",
            "Agrius",
            "Worm-Like Propagation",
            "Availability"
        ],  # Up to 10 tags
        "tactic": "Impact",  # Associated MITRE ATT&CK tactic
        "protocol": "N/A",  # Protocol used in the attack technique
        "os": "Linux, Network, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Monitor direct read/write attempts to sensitive disk areas (e.g., partition boot sector, superblock)",
            "Detect raw disk handle usage (e.g., \\\\.\\PhysicalDrive notation) in suspicious processes",
            "Watch for abnormal kernel driver installation or usage that may facilitate raw disk overwriting"
        ],
        "data_sources": "Command: Command Execution, Drive: Drive Access, Drive: Drive Modification, Driver: Driver Load, Process: Process Creation",
        "log_sources": [
            {
                "type": "Command",
                "source": "Process Monitoring",
                "destination": "SIEM"
            },
            {
                "type": "Drive",
                "source": "Disk/Volume Auditing",
                "destination": "SIEM"
            },
            {
                "type": "Driver",
                "source": "Driver Load Monitoring",
                "destination": "SIEM"
            },
            {
                "type": "Process",
                "source": "Endpoint Monitoring",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Disk Access Tools/Drivers",
                "location": "Local or remote system",
                "identify": "Utilities (e.g., RawDisk) enabling direct disk writes"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Wiped Disk Content",
                "location": "Target systems",
                "identify": "Corrupted disk sectors, overwritten data structures"
            }
        ],
        "detection_methods": [
            "Look for unusual process handle opens to raw disk volumes",
            "Correlate large-scale or multi-host disk wiping attempts with credential-based propagation",
            "Monitor for kernel drivers or specialized utilities that enable raw disk writes"
        ],
        "apt": [
            "APT33",
            "Lazarus",
            "Sandworm",
            "Agrius"
        ],  # APT groups known to use this technique
        "spl_query": [
            # Example Splunk query to detect raw disk access usage
            "index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational (EventID=10 TargetObject=\"\\\\.\\\\PhysicalDrive*\")\n| stats count by Image, ProcessId, TargetObject",
            # Example Splunk query to detect usage of vssadmin, wbadmin, or esentutl
            "index=main (Process_CommandLine=\"vssadmin\" OR Process_CommandLine=\"wbadmin\" OR Process_CommandLine=\"esentutl\")\n| stats count by host, user, Process_CommandLine"
        ],
        "hunt_steps": [
            "Identify processes or drivers that repeatedly open physical disk handles",
            "Check for references to RawDisk or similar third-party drivers in system logs",
            "Correlate disk wipe events with other destructive or worm-like behaviors"
        ],
        "expected_outcomes": [
            "Detection of disk content overwriting attempts aimed at rendering systems inoperable",
            "Identification of destructive malware that propagates to wipe multiple hosts",
            "Prevention of large-scale availability disruptions through early detection"
        ],
        "false_positive": "Legitimate disk imaging or backup processes may open raw disk handles. Validate context and authorized usage.",
        "clearing_steps": [
            "Restore affected disks from known good backups",
            "Terminate processes or drivers performing unauthorized disk writes",
            "Remove malicious binaries or drivers that enable raw disk overwriting"
        ],
        "mitre_mapping": [
            {
                "tactic": "Impact",
                "technique": "Disk Wipe: Disk Content Wipe (T1561.001)",
                "example": "Using direct disk access to overwrite disk sectors and disrupt system availability"
            }
        ],
        "watchlist": [
            "Processes referencing \\\\.\\PhysicalDrive or similar raw disk access",
            "Suspicious or newly installed drivers enabling raw disk read/write",
            "Multiple simultaneous disk write events across different hosts"
        ],
        "enhancements": [
            "Deploy file integrity or volume monitoring to detect unexpected disk modifications",
            "Implement strict access controls preventing unauthorized raw disk operations",
            "Use advanced EDR solutions to detect destructive behaviors and suspicious driver loads"
        ],
        "summary": "Adversaries may partially or completely overwrite disk content to disrupt system availability, often using raw disk access utilities or specialized drivers. This destructive tactic may propagate across a network to maximize impact on an organization.",
        "remediation": "Restrict raw disk access to authorized processes, monitor for malicious driver loads, and maintain robust offline backups to recover from disk wiping events.",
        "improvements": "Enable advanced logging and auditing of disk-level operations, train responders to detect destructive disk access attempts, and enforce least privilege on accounts with disk modification rights."
    }
