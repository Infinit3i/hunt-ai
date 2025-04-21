def get_content():
    return {
        "id": "T1564",
        "url_id": "T1564",
        "title": "Hide Artifacts",
        "description": "Adversaries may attempt to hide artifacts associated with their behaviors to evade detection. Operating systems may have features to hide various artifacts, such as important system files and administrative task execution, to avoid disrupting user work environments and prevent users from changing files or features on the system. Adversaries may abuse these features to hide artifacts such as files, directories, user accounts, or other system activity to evade detection. Adversaries may also attempt to hide artifacts associated with malicious behavior by creating computing regions that are isolated from common security instrumentation, such as through the use of virtualization technology.",
        "tags": ["evasion", "stealth", "hiding", "obfuscation", "artifact manipulation"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Office Suite, Windows, macOS",
        "tips": [
            "Monitor event logs for hidden service creation",
            "Audit registry key modifications involving hidden settings",
            "Correlate process activity with hidden file access patterns"
        ],
        "data_sources": "Application Log, Command, File, Firmware, Process, Script, Service, User Account, Windows Registry",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Firmware", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Script", "source": "", "destination": ""},
            {"type": "Service", "source": "", "destination": ""},
            {"type": "User Account", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Sysmon Logs", "location": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx", "identify": "Look for file creation or manipulation with hidden attributes"},
            {"type": "Windows Defender Logs", "location": "C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\", "identify": "Hidden threat detections"},
            {"type": "File Access Times (MACB Timestamps)", "location": "NTFS file system", "identify": "Hidden creation/modification times"},
            {"type": "Registry Hives", "location": "HKLM\\SYSTEM or HKCU\\Software", "identify": "Hidden or suspicious keys"},
            {"type": "Process List", "location": "RAM image or Sysmon", "identify": "Hidden or masked processes"}
        ],
        "destination_artifacts": [
            {"type": "Sysmon Logs", "location": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx", "identify": "File or process activity with hidden flags"},
            {"type": "Registry Hives", "location": "HKLM\\SYSTEM or HKCU\\Software", "identify": "Persistence via hidden keys"},
            {"type": "Loaded DLLs", "location": "Process Memory", "identify": "Stealth injection artifacts"},
            {"type": "File Access Times (MACB Timestamps)", "location": "Target filesystem", "identify": "Inconsistent timestamps indicating artifact hiding"},
            {"type": "Services", "location": "services.msc", "identify": "Suspicious or hidden services"}
        ],
        "detection_methods": [
            "Monitor file system for hidden attribute toggling (attrib +h)",
            "Detect processes interacting with hidden files",
            "Check for unexpected registry keys in auto-start entries",
            "Search for discrepancies in process listings across tools"
        ],
        "apt": ["Sofacy", "Pirrit", "DarkTortilla", "Shlayer", "Warzone", "Ragnar", "Tarrask"],
        "spl_query": [
            "index=sysmon EventCode=11 FileAttributes=*hidden* \n| stats count by Image, TargetFilename",
            "index=security EventCode=7045 ServiceName=* \n| search ServiceType=kerneldriver StartType=demand \n| where Description contains \"hidden\"",
            "index=sysmon EventCode=1 \n| search CommandLine=*attrib*+h* \n| stats count by CommandLine, ParentImage, User"
        ],
        "hunt_steps": [
            "Identify files with hidden attribute in user directories",
            "Check for registry entries with suspicious keys or no descriptions",
            "Compare tasklist with Sysinternals PsList to identify hidden processes"
        ],
        "expected_outcomes": [
            "Detection of hidden files or directories being accessed",
            "Discovery of registry keys linked to hidden services",
            "Identification of stealth malware attempting to evade visibility"
        ],
        "false_positive": "Administrators and some programs may intentionally use hidden attributes for system or configuration files. Verify intent before taking action.",
        "clearing_steps": [
            "Remove hidden attribute from suspicious files: attrib -h <file>",
            "Terminate hidden processes using Task Manager or Sysinternals PsKill",
            "Delete registry entries created for stealthy persistence",
            "Audit logs for related activity and remove secondary artifacts"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1070.004", "example": "Clear Windows Event Logs after hiding artifacts"},
            {"tactic": "Persistence", "technique": "T1543.003", "example": "Create hidden service for stealthy startup"}
        ],
        "watchlist": [
            "Repeated use of attrib command",
            "Unusual registry key creation",
            "Files created with system and hidden attributes"
        ],
        "enhancements": [
            "Use file integrity monitoring tools to track hidden file changes",
            "Enable auditing on key registry paths",
            "Correlate logon events with hidden file manipulations"
        ],
        "summary": "Adversaries may hide files, processes, or registry entries to evade detection. This technique is often used with stealth malware to persist silently on a system.",
        "remediation": "Unhide, quarantine, and remove files or services. Revoke persistence and validate through integrity monitoring and endpoint protection logs.",
        "improvements": "Deploy behavior-based detection on endpoints and conduct routine integrity checks on system directories and startup configurations.",
        "mitre_version": "16.1"
    }
