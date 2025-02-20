def get_content():
    """
    Returns structured content for the Match Legitimate Names of Windows Processes method.
    """
    return {
        "id": "T1036.005",
        "url_id": "T1036/005",
        "title": "Match Legitimate Names of Windows Processes",
        "tactic": "Defense Evasion",
        "data_sources": "Windows Event Logs, File Monitoring, Process Monitoring",
        "protocol": "N/A",
        "os": "Windows",
        "objective": "Adversaries may rename malicious processes to match legitimate Windows processes to evade detection.",
        "scope": "Monitor running processes and executable file names for discrepancies.",
        "threat_model": "Attackers may use process masquerading by renaming malicious executables to match legitimate Windows process names.",
        "hypothesis": [
            "Are multiple instances of critical system processes running simultaneously?",
            "Are there discrepancies between the executable file path and its expected location?",
            "Is a process with a legitimate Windows name exhibiting unusual behavior?"
        ],
        "tips": [
            "Compare process executable paths with expected Windows system locations.",
            "Monitor process command-line arguments for unexpected usage.",
            "Analyze file hashes of running processes to detect mismatches."
        ],
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Security.evtx", "destination": "System.evtx"},
            {"type": "File Monitoring", "source": "Windows Defender Logs"},
            {"type": "Process Monitoring", "source": "Sysmon Event ID 1, Event ID 4688"}
        ],
        "source_artifacts": [
            {"type": "Prefetch", "location": "C:\\Windows\\Prefetch", "identify": "Malicious masquerading processes"}
        ],
        "destination_artifacts": [
            {"type": "File System", "location": "C:\\Windows\\System32", "identify": "Unexpected file modifications"}
        ],
        "detection_methods": [
            "Monitor process creation logs for unexpected executable names.",
            "Analyze process execution locations to detect anomalies.",
            "Check for duplicate process names running from unusual paths."
        ],
        "apt": ["G0016", "G0020"],
        "spl_query": [
            "index=windows EventCode=4688 NewProcessName!=C:\\Windows\\System32\\* | table Time, NewProcessName, ParentProcessName",
            "index=windows EventCode=1 Image!=C:\\Windows\\System32\\* | table Time, Image, CommandLine"
        ],
        "hunt_steps": [
            "Identify processes running with unexpected file paths.",
            "Verify process hashes against known-good Windows binaries.",
            "Investigate suspicious command-line arguments and process behaviors."
        ],
        "expected_outcomes": [
            "Unauthorized masquerading process detected and mitigated.",
            "No malicious activity found, refining baseline monitoring."
        ],
        "false_positive": "Some legitimate third-party applications may use system process names.",
        "clearing_steps": [
            "Terminate suspicious processes via Task Manager or PowerShell.",
            "Remove malicious executable from system directories."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1036 (Masquerading)", "example": "Adversaries rename processes to evade detection."}
        ],
        "watchlist": [
            "Monitor duplicate process names with different execution paths.",
            "Detect execution of system processes from non-standard locations."
        ],
        "enhancements": [
            "Enforce application control policies to restrict unauthorized executions.",
            "Utilize endpoint protection solutions to detect process masquerading."
        ],
        "summary": "Attackers may rename malicious processes to match legitimate Windows processes to evade detection.",
        "remediation": "Terminate rogue processes, remove associated files, and investigate for further compromise.",
        "improvements": "Enhance monitoring for process execution paths and command-line arguments."
    }
