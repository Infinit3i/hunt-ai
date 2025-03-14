def get_content():
    return {
        "id": "T1010",  # Tactic Technique ID
        "url_id": "1010",  # URL segment for technique reference
        "title": "Application Window Discovery",  # Name of the attack technique
        "description": "Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used. For example, information about application windows could be used to identify potential data to collect as well as identifying security tooling to evade.",  # Description of the attack technique
        "tags": ["Discovery", "Application Enumeration"],  # Tags associated with the technique
        "tactic": "Discovery",  # Associated MITRE ATT&CK tactic
        "protocol": "",  # No specific protocol
        "os": "Linux, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Monitor processes and command-line arguments for actions that gather system and network information.",
            "Detect attempts to enumerate open application windows.",
            "Analyze behaviors of remote access tools interacting with the Windows API."
        ],  # Additional investigation and mitigation tips
        "data_sources": "Command Execution, Process Creation, OS API Execution",  # Relevant data sources
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": "Windows Event Logs"},
            {"type": "Process", "source": "OS API Execution", "destination": "Sysmon"},
            {"type": "Process", "source": "Process Creation", "destination": "Security Logs"}
        ],  # Logs necessary for detection
        "source_artifacts": [
            {"type": "Process", "location": "Task Manager", "identify": "Active processes and windows"}
        ],  # Artifacts on the source machine
        "destination_artifacts": [],  # No destination artifacts
        "detection_methods": [
            "Monitor API calls related to window enumeration.",
            "Track unusual command-line executions that query active windows."
        ],  # Techniques for identifying the attack
        "apt": ["APT37", "APT41", "Naikon", "Grandoreiro"], # APT groups known to use this technique
        "spl_query": [
            "index=windows EventCode=4688 CommandLine=*tasklist*",
            "index=windows EventCode=4688 CommandLine=*wmic process*"
        ],  # Splunk queries to detect the technique
        "hunt_steps": [
            "Identify anomalous execution of tasklist or wmic commands.",
            "Check for unauthorized scripts performing window enumeration.",
            "Analyze logs for unusual process executions."
        ],  # Steps to proactively hunt for threats
        "expected_outcomes": [
            "Detection of unauthorized enumeration of application windows.",
            "Identification of potential evasion techniques used by adversaries."
        ],  # Expected results from detection/hunting
        "false_positive": "Legitimate administrative tools may perform similar actions. Context analysis is required.",  # Known false positives and handling methods
        "clearing_steps": [
            "Terminate unauthorized enumeration processes.",
            "Review system logs and security events for signs of compromise.",
            "Enhance endpoint detection rules to flag suspicious window enumeration attempts."
        ],  # Steps for remediation and clearing traces
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "Process Discovery", "example": "Adversaries may enumerate running processes after identifying open windows."},
            {"tactic": "Evasion", "technique": "Obfuscated Files or Information", "example": "Adversaries may use obfuscation techniques to hide enumeration activity."}
        ],  # Next MITRE Techniques that could follow
        "watchlist": [
            "Unusual execution of process listing commands.",
            "Unexpected scripts accessing the Windows API."
        ],  # Indicators to monitor
        "enhancements": [
            "Implement behavioral-based anomaly detection for application discovery attempts.",
            "Enable process auditing and logging for security analysis."
        ],  # Suggested improvements to detection
        "summary": "Application Window Discovery is a reconnaissance technique used by adversaries to gather information about open application windows on a system. This information can be leveraged to identify sensitive data or evade security defenses.",  # High-level summary
        "remediation": "Monitor and restrict access to process enumeration tools. Implement user behavior analytics to detect anomalies.",  # Recommended actions
        "improvements": "Enhance security policies to restrict unnecessary access to process and application enumeration commands."  # Suggested improvements
    }
