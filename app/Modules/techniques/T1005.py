def get_content():
    return {
        "id": "T1005",  # Tactic Technique ID
        "url_id": "1005",  # URL segment for technique reference
        "title": "Data from Local System",  # Name of the attack technique
        "description": "Adversaries may search local system sources (e.g., file systems, local databases) to find files of interest and sensitive data prior to exfiltration, potentially using built-in OS commands, scripts, or specialized tools.",  # Simple description
        "tags": [
            "Data from Local System",
            "Local Data",
            "Collection",
            "OS API Execution",
            "File Access",
            "Mandiant APT41",
            "PowerShell",
            "WMI",
            "Network Device CLI",
            "Windows"
        ],  # Up to 10 tags
        "tactic": "Collection",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "Linux, Network, Windows, macOS",  # Targeted operating systems/environments
        "tips": [
            "Monitor processes/commands that enumerate or copy large volumes of files",
            "Inspect unusual file system or registry accesses, especially by non-standard processes",
            "Audit use of built-in OS tools (e.g., PowerShell, WMI) and Network Device CLI commands"
        ],
        "data_sources": "Command: Command Execution, File: File Access, Process: OS API Execution, Process: Process Creation, Script: Script Execution",
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
                "type": "Process",
                "source": "Endpoint Monitoring",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Local Files/Data",
                "location": "File system, local databases, configuration files",
                "identify": "Sensitive information (e.g., credentials, internal documentation)"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Staged Data",
                "location": "Temporary directories or adversary-controlled locations",
                "identify": "Aggregated files prepared for exfiltration"
            }
        ],
        "detection_methods": [
            "Correlate file access events with suspicious process execution or account usage",
            "Look for batch or script-based collection activities, including archiving or encryption",
            "Monitor OS-level commands (e.g., show, copy, move) and unusual PowerShell/WMI usage"
        ],
        "apt": [
            "APT41",
            "FIN6",
            "APT1"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Identify processes repeatedly enumerating multiple directories or drives",
            "Check for newly created archives (e.g., .zip, .rar) in suspicious locations",
            "Correlate unusual file access times with user login/logoff events"
        ],
        "expected_outcomes": [
            "Discovery of adversary file collection or local data staging",
            "Detection of unauthorized scripts or tools used to harvest sensitive information",
            "Identification of compromised accounts used to access high-value data"
        ],
        "false_positive": "Legitimate data backups or system maintenance may exhibit similar behaviors. Validate context, scheduling, and authorized processes.",
        "clearing_steps": [
            "Terminate malicious processes responsible for unauthorized file collection",
            "Quarantine or remove staging archives and tools",
            "Review and tighten file permissions to restrict unauthorized access"
        ],
        "mitre_mapping": [
            {
                "tactic": "Collection",
                "technique": "Data from Local System (T1005)",
                "example": "Using OS commands or scripts to locate and gather sensitive files"
            }
        ],
        "watchlist": [
            "Processes accessing large volumes of files in a short time span",
            "Unexpected archive or encryption utilities appearing in unusual directories",
            "Network device commands retrieving config files from routers/switches"
        ],
        "enhancements": [
            "Enable file integrity monitoring for critical directories",
            "Deploy EDR solutions capable of detecting unusual file access patterns",
            "Implement strict least privilege for user accounts and processes"
        ],
        "summary": "Adversaries gather data from local systems to obtain sensitive information, using built-in commands or scripts to search, copy, and prepare files for exfiltration.",
        "remediation": "Implement robust access controls, monitor system processes, and promptly investigate anomalies in file access and system utilities usage.",
        "improvements": "Regularly audit file permissions, apply behavioral analysis to detect suspicious file collection patterns, and use network segmentation to limit lateral movement opportunities."
    }
