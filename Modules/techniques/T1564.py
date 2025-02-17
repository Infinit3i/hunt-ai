def get_content():
    """
    Returns structured content for the Hide Artifacts technique (T1564).
    """
    return {
        "id": "T1564",
        "url_id": "T1564",
        "title": "Hide Artifacts",
        "tactic": "Defense Evasion",
        "data_sources": "Windows Event Logs, File Monitoring, Process Monitoring",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries may attempt to hide artifacts to avoid detection.",
        "scope": "Monitor system changes and hidden files or processes.",
        "threat_model": "Attackers often attempt to conceal files, processes, or registry keys to evade detection.",
        "hypothesis": [
            "Are there hidden files or processes executing on the system?",
            "Are adversaries using rootkits or hidden directories for persistence?",
            "Are registry keys being manipulated to mask artifacts?"
        ],
        "tips": [
            "Monitor for hidden files and directories using forensic tools.",
            "Detect suspicious process injections and rootkit behavior.",
            "Check for hidden registry modifications."
        ],
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Security.evtx", "destination": "System.evtx"},
            {"type": "File Monitoring", "source": "Hidden file scans"},
            {"type": "Process Monitoring", "source": "Rootkit detection tools"}
        ],
        "source_artifacts": [
            {"type": "Hidden Files", "location": "System and user directories", "identify": "Suspicious file names or attributes"}
        ],
        "destination_artifacts": [
            {"type": "Registry Entries", "location": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "identify": "Hidden registry keys"}
        ],
        "detection_methods": [
            "Monitor file system changes for hidden files and directories.",
            "Analyze process execution to detect injected or hidden processes.",
            "Use registry monitoring tools to identify hidden entries."
        ],
        "apt": ["G0010", "G0035"],
        "spl_query": [
            "index=windows EventCode=4688 | search ImagePath=*hidden*",
            "index=linux | search Hidden File Detection"
        ],
        "hunt_steps": [
            "Scan file system for hidden artifacts.",
            "Monitor process execution for hidden behavior.",
            "Check registry for anomalies related to hidden persistence."
        ],
        "expected_outcomes": [
            "Hidden artifacts identified and mitigated.",
            "No hidden activity detected, refining detection mechanisms."
        ],
        "false_positive": "Legitimate security tools or administrators may use hidden files for protection.",
        "clearing_steps": [
            "Remove hidden files using forensic tools.",
            "Delete hidden registry entries using regedit."] ,
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1564 (Hide Artifacts)", "example": "Attackers hiding files in alternate data streams."}
        ],
        "watchlist": [
            "Monitor for hidden files and suspicious file attributes.",
            "Detect hidden processes or injected DLLs."
        ],
        "enhancements": [
            "Enable forensic file integrity monitoring.",
            "Use process monitoring tools to detect hidden execution."
        ],
        "summary": "Attackers use various techniques to hide files, processes, or registry entries to evade detection.",
        "remediation": "Remove hidden artifacts and improve detection for hidden threats.",
        "improvements": "Enhance monitoring of file and process behavior to detect hidden persistence."
    }
