def get_content():
    return {
        "id": "T1560.003",  # Tactic Technique ID
        "url_id": "1560/003",  # URL segment for technique reference
        "title": "Archive Collected Data: Archive via Custom Method",  # Name of the attack technique
        "description": "An adversary may compress or encrypt data that is collected prior to exfiltration using a custom method. Adversaries may choose to use custom archival methods, such as encryption with XOR or stream ciphers implemented with no external library or utility references. Custom implementations of well-known compression algorithms have also been used.",
        "tags": ["Collection", "Archival", "Custom Methods"],  # Tags associated with the technique
        "tactic": "Collection",  # Associated MITRE ATT&CK tactic
        "protocol": "N/A",  # Protocol used in the attack technique
        "os": "Linux, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Monitor for uncommon or custom encryption techniques in file creation logs.",
            "Analyze script execution behavior for unusual bitwise operations.",
            "Track changes in file headers to detect non-standard compression methods."
        ],  # Additional investigation and mitigation tips
        "data_sources": "File: File Creation, Script: Script Execution",  # Relevant data sources
        "log_sources": [
            {"type": "File", "source": "File Creation", "destination": "System Logs"},
            {"type": "Script", "source": "Script Execution", "destination": "Monitoring Tools"}
        ],  # Logs necessary for detection
        "source_artifacts": [
            {"type": "File", "location": "User Directories", "identify": "Unusual Archive Formats"}
        ],  # Artifacts generated on the source machine
        "destination_artifacts": [
            {"type": "File", "location": "External Storage or Network Drive", "identify": "Compressed Data"}
        ],  # Artifacts generated on the destination machine
        "detection_methods": [
            "Monitor for non-standard file compression tools.",
            "Detect script executions performing large-scale XOR operations.",
            "Analyze entropy levels of newly created files to identify potential encryption."
        ],  # Techniques for identifying the attack
        "apt": ["FIN6", "Lazarus Group", "APT30", "UNC3890"],  # APT groups known to use this technique
        "spl_query": [
            "index=main source=/var/log/syslog \n| search script_execution custom_compression"
        ],  # Splunk queries to detect the technique
        "hunt_steps": [
            "Identify recent file creation events with unexpected extensions.",
            "Check for processes performing excessive XOR or encryption loops.",
            "Inspect network transfers containing large compressed files."
        ],  # Steps to proactively hunt for threats
        "expected_outcomes": [
            "Discovery of suspicious compression or encryption activities.",
            "Identification of unexpected archive tools within the environment."
        ],  # Expected results from detection/hunting
        "false_positive": "Compression and encryption activities can be legitimate. Analyze context and user behavior.",  # Known false positives and how to handle them
        "clearing_steps": [
            "Delete unauthorized archive files.",
            "Terminate suspicious processes associated with custom encryption.",
            "Revoke access to storage drives if unauthorized activity is detected."
        ],  # Steps for remediation and clearing traces
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "Exfiltration Over Alternative Protocol", "example": "Compressed files sent over covert channels."}
        ],  # Next MITRE Technique that could be used after this technique
        "watchlist": [
            "Unusual file creation patterns in system directories.",
            "High entropy files appearing in unexpected locations."
        ],  # Indicators to monitor for potential threats
        "enhancements": [
            "Implement strict access control on compression utilities.",
            "Use automated entropy analysis on new files to detect potential encryption."
        ],  # Suggested improvements to detection
        "summary": "Adversaries may use custom methods to archive collected data before exfiltration, making detection challenging.",  # High-level summary
        "remediation": "Block unauthorized encryption and compression tools, monitor file activities, and investigate anomalies in script execution.",  # Recommended actions to mitigate risk
        "improvements": "Enhance security policies to limit access to custom archive utilities, deploy file integrity monitoring, and increase visibility into file transfers."
    }
