def get_content():
    return {
        "id": "T1561.002",
        "url_id": "T1561/002",
        "title": "Disk Wipe: Disk Structure Wipe",
        "description": "Adversaries may corrupt or wipe the disk data structures on a hard drive necessary to boot a system.",
        "tags": [
            "t1561.002", "disk wipe", "disk structure wipe", "impact", "availability", "windows", "linux", "macos", "network"
        ],
        "tactic": "Impact",
        "protocol": "",
        "os": "Linux, Network, Windows, macOS",
        "tips": [
            "Look for attempts to read/write to sensitive disk locations like the master boot record or partition table.",
            "Monitor direct access attempts using \\\\.\\ notation.",
            "Watch for unusual driver load or kernel mode activity."
        ],
        "data_sources": "Command: Command Execution, Drive: Drive Access, Drive: Drive Modification, Driver: Driver Load, Process: Process Creation",
        "log_sources": [
            {"type": "Drive", "source": "Raw Disk Access", "destination": "Security Monitoring"},
            {"type": "Process", "source": "Driver Load", "destination": "Sysmon or Kernel Logs"}
        ],
        "source_artifacts": [
            {"type": "Executable", "location": "System32 or /bin", "identify": "MBR Wipe Tool or Wiper Malware"}
        ],
        "destination_artifacts": [
            {"type": "Disk", "location": "\\\\.\\PhysicalDrive0", "identify": "Overwritten MBR or Partition Table"}
        ],
        "detection_methods": [
            "Detect use of raw disk write APIs.",
            "Monitor for use of \"format\" or \"dd\" on system drives.",
            "Analyze Sysmon Event ID 6 (driver load)."
        ],
        "apt": ["Shamoon", "APT37", "APT38", "Agrius", "WhisperGate", "Telebots"],
        "spl_query": [
            "index=windows_logs EventCode=6 ImageLoaded=*\\*\\sys*", 
            "index=linux_logs process_name=dd AND command_line=*if=*/dev/sd*"
        ],
        "hunt_steps": [
            "Identify attempts to write to the MBR or partition table.",
            "Check for tools or malware capable of performing disk wipes.",
            "Hunt for suspicious use of \"format\" or \"diskpart\" commands."
        ],
        "expected_outcomes": [
            "Detection of malicious activity targeting disk boot structures.",
            "Prevention or early warning of destructive malware execution."
        ],
        "false_positive": "Low, as MBR/partition writes are rare and usually tied to disk maintenance or OS installs.",
        "clearing_steps": [
            "Reimage the affected system from trusted media.",
            "Investigate lateral movement paths used by the adversary.",
            "Restore from clean backups."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1070", "example": "Wiping disk to remove forensic evidence"}
        ],
        "watchlist": [
            "Disk modification activity to \\\\.\\PhysicalDrive0",
            "Unexpected use of \"format\" or \"diskpart\" commands"
        ],
        "enhancements": [
            "Implement disk integrity monitoring.",
            "Limit low-level disk access to administrative tools only."
        ],
        "summary": "Adversaries may wipe disk structures such as the MBR or partition table to render systems unbootable.",
        "remediation": "Reimage compromised systems and block tools used in disk modification.",
        "improvements": "Deploy application controls to block execution of raw disk writers."
    }
