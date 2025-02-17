def get_content():
    """
    Returns structured content for the Ingress Tool Transfer technique (T1105).
    """
    return {
        "id": "T1105",
        "url_id": "T1105",
        "title": "Ingress Tool Transfer",
        "tactic": "Command and Control, Defense Evasion",
        "data_sources": "Network Traffic, File Monitoring, Process Monitoring",
        "protocol": "HTTP, HTTPS, FTP, SMB, SFTP",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries may transfer tools or payloads onto a system to facilitate execution or further compromise.",
        "scope": "Monitor file transfer activities and abnormal network connections.",
        "threat_model": "Attackers use various protocols to transfer malicious tools to a compromised system for further exploitation.",
        "hypothesis": [
            "Are unauthorized files being transferred into the environment?",
            "Are known attacker toolsets being downloaded?",
            "Are files being transferred from suspicious external sources?"
        ],
        "tips": [
            "Monitor for unusual file downloads and execution of non-standard tools.",
            "Detect unauthorized network connections facilitating file transfers.",
            "Inspect logs for signs of suspicious data ingress or remote file execution."
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "Firewall Logs, Proxy Logs", "destination": "Endpoint Logs"},
            {"type": "File Monitoring", "source": "File System Logs", "destination": "SIEM"},
            {"type": "Process Monitoring", "source": "Sysmon Event ID 1, Windows Event Logs 4688"}
        ],
        "source_artifacts": [
            {"type": "File Creation", "location": "C:\\Users\\Public", "identify": "Unexpected executables"},
            {"type": "Process Execution", "location": "Task Scheduler, PowerShell", "identify": "Suspicious script executions"}
        ],
        "destination_artifacts": [
            {"type": "Network Traffic", "location": "Inbound network connections", "identify": "External tool downloads"}
        ],
        "detection_methods": [
            "Analyze network traffic for unexpected file transfers.",
            "Monitor process creation for execution of transferred files.",
            "Identify unauthorized execution of downloaded binaries."
        ],
        "apt": ["G0032", "G0016"],
        "spl_query": [
            "index=network_protocols AND (file_transfer OR unauthorized_downloads)",
            "index=windows EventCode=4688 CommandLine IN ('certutil.exe', 'powershell Invoke-WebRequest', 'bitsadmin.exe')"
        ],
        "hunt_steps": [
            "Review proxy and firewall logs for unauthorized file downloads.",
            "Check for unusual network connections to suspicious domains.",
            "Investigate execution of newly downloaded files on endpoints."
        ],
        "expected_outcomes": [
            "Unauthorized file transfer detected and blocked.",
            "No malicious activity found, refining monitoring baselines."
        ],
        "false_positive": "Legitimate software updates or administrator actions may trigger similar behavior.",
        "clearing_steps": [
            "Delete unauthorized files from infected systems.",
            "Terminate suspicious processes executing downloaded files."],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1071.001 (Web Protocols for C2)", "example": "Attackers may use web protocols to transfer tools."}
        ],
        "watchlist": [
            "Monitor tools like certutil, bitsadmin, or PowerShell downloading remote files.",
            "Flag execution of unsigned binaries from unexpected locations."
        ],
        "enhancements": [
            "Implement network-based file transfer restrictions.",
            "Use endpoint protection to block execution of unauthorized downloads."
        ],
        "summary": "Ingress Tool Transfer involves downloading or copying files to a compromised system, often for further exploitation.",
        "remediation": "Quarantine affected endpoints and remove unauthorized files, blocking malicious domains.",
        "improvements": "Strengthen network monitoring and endpoint protection to prevent unauthorized file transfers."
    }
