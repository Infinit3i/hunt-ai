def get_content():
    return {
        "id": "T1561",  # Tactic Technique ID
        "url_id": "1561",  # URL segment for technique reference
        "title": "Disk Wipe",  # Name of the attack technique
        "description": "Adversaries may wipe or corrupt raw disk data on specific systems or in large numbers across a network to interrupt system and network resource availability. This may involve overwriting arbitrary disk data, critical disk structures like the master boot record (MBR), or even a complete wipe of all disk sectors. Malware used for network-wide disk wiping may propagate via techniques such as Valid Accounts, OS Credential Dumping, and SMB/Windows Admin Shares. On network devices, adversaries may wipe configuration files using commands such as `erase`.",  # Simple description
        "tags": [
            "Disk Wipe",
            "MBR Overwrite",
            "Network Device CLI",
            "SMB/Windows Admin Shares",
            "OS Credential Dumping",
            "Valid Accounts",
            "Novetta Blockbuster Destructive Malware",
            "Microsoft Sysmon v6 May 2017",
            "erase_cmd_cisco",
            "Ready.gov IT DRP"
        ],  # Up to 10 tags
        "tactic": "Impact",  # Associated MITRE ATT&CK tactic
        "protocol": "N/A",  # Protocol used in the attack technique
        "os": "Linux, Network, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Monitor direct read/write attempts to disk sectors (e.g., MBR, partition table) via raw disk handles",
            "Use file integrity monitoring or endpoint security solutions to detect abnormal disk access patterns",
            "Look for suspicious driver installation or usage that could facilitate raw disk writes"
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
                "type": "Disk Access Tools",
                "location": "Local system or network device",
                "identify": "Utilities (e.g., direct volume handles, `erase` CLI, raw disk writes)"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Wiped or Corrupted Disk Data",
                "location": "Target systems",
                "identify": "Overwritten disk sectors, corrupted MBR, or removed configuration files"
            }
        ],
        "detection_methods": [
            "Monitor for unusual handle opens to raw disk volumes (\\\\.\\ notation on Windows)",
            "Analyze driver loading for suspicious or unauthorized disk-access drivers",
            "Look for processes or scripts issuing direct disk write commands, including CLI commands like `erase`"
        ],
        "apt": [],
        "spl_query": [],
        "hunt_steps": [
            "Identify processes that attempt raw disk access outside of legitimate imaging or maintenance activities",
            "Correlate large-scale or multi-host disk wiping attempts with other intrusion indicators",
            "Examine logs for unauthorized usage of device management commands on network devices"
        ],
        "expected_outcomes": [
            "Detection of attempts to disrupt availability by wiping disk data or configurations",
            "Identification of compromised hosts or devices targeted for destructive operations",
            "Prevention of large-scale disk wiping campaigns by timely detection and response"
        ],
        "false_positive": "Legitimate disk imaging or maintenance tasks may mimic raw disk write activity. Validate context and user permissions.",
        "clearing_steps": [
            "Restore systems from known good backups or disk images",
            "Block or remove malicious processes and drivers responsible for raw disk writes",
            "Strengthen credential and network share protections to limit worm-like propagation"
        ],
        "mitre_mapping": [
            {
                "tactic": "Impact",
                "technique": "Disk Wipe (T1561)",
                "example": "Overwriting disk sectors or MBR to render systems inoperable"
            }
        ],
        "watchlist": [
            "Processes referencing raw disk handles (e.g., \\\\.\\PhysicalDrive0)",
            "Network device logs indicating `erase` or equivalent destructive commands",
            "Driver loads or processes that exhibit large-scale write operations to disks"
        ],
        "enhancements": [
            "Deploy advanced EDR solutions to alert on abnormal disk operations",
            "Maintain regular offline backups to mitigate data destruction events",
            "Implement strict access controls and monitoring for critical system volumes"
        ],
        "summary": "Disk wiping involves overwriting or corrupting disk data (including critical structures like the MBR) to disrupt availability of systems. Adversaries may leverage direct volume access or specialized commands/utilities to perform large-scale destructive operations, potentially propagating via stolen credentials or admin shares to maximize impact.",
        "remediation": "Restrict direct disk access to privileged accounts, closely monitor for suspicious disk write attempts, and maintain robust backup/restore capabilities for critical systems.",
        "improvements": "Enable low-level disk auditing, enforce least privilege on system accounts, and train incident responders to quickly detect and respond to destructive disk operations."
    }
