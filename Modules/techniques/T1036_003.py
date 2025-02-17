def get_content():
    """
    Returns structured content for the Rename System Utilities technique.
    """
    return {
        "id": "T1036.003",
        "url_id": "T1036/003",
        "title": "Masquerading: Rename System Utilities",
        "tactic": "Defense Evasion",
        "data_sources": "Process Execution, File Monitoring, Windows Event Logs",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries rename system utilities to evade detection by security monitoring tools.",
        "scope": "Monitor process execution and file system changes to detect renamed system utilities.",
        "threat_model": "Attackers may rename built-in system utilities to disguise malicious activity.",
        "hypothesis": [
            "Are system utilities running from unusual locations?",
            "Are known system utilities executing under unexpected names?",
            "Are attackers using renamed binaries to avoid detection?"
        ],
        "tips": [
            "Monitor execution of renamed binaries in critical system paths.",
            "Analyze file creation events for suspicious copies of system utilities.",
            "Compare running processes against a list of known system utilities."
        ],
        "log_sources": [
            {"type": "Process Execution", "source": "Sysmon Event ID 1", "destination": "Security.evtx"},
            {"type": "File Monitoring", "source": "Sysmon Event ID 11", "destination": "File System Logs"},
            {"type": "Windows Event Logs", "source": "Event ID 4688", "destination": "Security.evtx"}
        ],
        "source_artifacts": [
            {"type": "Prefetch", "location": "C:\\Windows\\Prefetch", "identify": "Renamed system utilities"}
        ],
        "destination_artifacts": [
            {"type": "Executable Files", "location": "C:\\Windows\\System32", "identify": "Modified or renamed system utilities"}
        ],
        "detection_methods": [
            "Monitor process execution with abnormal names matching known system utilities.",
            "Track file creation events for renamed system binaries.",
            "Use hash analysis to identify renamed but unmodified executables."
        ],
        "apt": ["G0016", "G0045"],
        "spl_query": [
            "index=windows EventCode=4688 NewProcessName!=C:\\Windows\\System32\\* | table Time, NewProcessName, ParentProcessName",
            "index=windows EventCode=1 Image!=C:\\Windows\\System32\\* | table Time, Image, CommandLine"
        ],
        "hunt_steps": [
            "Identify renamed system utilities executing from non-standard paths.",
            "Correlate process execution with file creation logs.",
            "Analyze process lineage to detect suspicious renaming activity."
        ],
        "expected_outcomes": [
            "Detection of renamed system utilities used in evasion tactics.",
            "No suspicious activity found, improving baseline detection."
        ],
        "false_positive": "Administrators may rename system utilities for legitimate use, requiring context validation.",
        "clearing_steps": [
            "Identify and remove renamed system utilities from unauthorized locations.",
            "Update security monitoring tools to track renamed binary execution."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1036 (Masquerading)", "example": "Attackers rename system utilities to evade detection."}
        ],
        "watchlist": [
            "Monitor execution of renamed system utilities.",
            "Detect abnormal process execution locations."
        ],
        "enhancements": [
            "Implement file integrity monitoring on critical system paths.",
            "Use application whitelisting to restrict execution of renamed binaries."
        ],
        "summary": "Adversaries rename system utilities to avoid detection and blend into normal operations.",
        "remediation": "Remove unauthorized renamed utilities and enforce execution control policies.",
        "improvements": "Enhance logging and monitoring to detect renamed system utilities more effectively."
    }
