def get_content():
    """
    Returns structured content for the Parent PID Spoofing technique (T1134.004).
    """
    return {
        "id": "T1134.004",
        "url_id": "T1134/004",
        "title": "Access Token Manipulation: Parent PID Spoofing",
        "tactic": "Defense Evasion, Privilege Escalation",
        "data_sources": "Process Monitoring, Windows Event Logs, Security Logs",
        "protocol": "N/A",
        "os": "Windows",
        "objective": "Adversaries may manipulate the parent process identifier (PPID) to evade detection or escalate privileges.",
        "scope": "Monitor process execution and relationships between parent and child processes.",
        "threat_model": "Attackers may modify the PPID to make malicious processes appear as if they were spawned by legitimate ones.",
        "hypothesis": [
            "Are there processes with unusual parent-child relationships?",
            "Are attackers leveraging PPID spoofing to bypass security controls?",
            "Are privileged processes being spawned by unexpected parents?"
        ],
        "tips": [
            "Monitor process creation logs for anomalies in parent-child relationships.",
            "Analyze security logs for evidence of privilege escalation attempts.",
            "Detect tools commonly used for PPID spoofing (e.g., PowerShell, Cobalt Strike)."
        ],
        "log_sources": [
            {"type": "Process Monitoring", "source": "Sysmon Event ID 1", "destination": "Security.evtx"},
            {"type": "Windows Event Logs", "source": "Event ID 4688", "destination": "Security.evtx"}
        ],
        "source_artifacts": [
            {"type": "Prefetch", "location": "C:\\Windows\\Prefetch", "identify": "Suspicious process launches"}
        ],
        "destination_artifacts": [
            {"type": "Process Execution", "location": "C:\\Windows\\System32", "identify": "Spoofed processes"}
        ],
        "detection_methods": [
            "Monitor child processes launched with unexpected parent processes.",
            "Detect tools that modify process tokens to spoof parent processes.",
            "Analyze command-line arguments for suspicious execution parameters."
        ],
        "apt": ["G0016", "G0032"],
        "spl_query": [
            "index=windows EventCode=4688 NewProcessName=* | table Time, ParentProcessName, NewProcessName, UserName",
            "index=windows EventCode=1 ParentProcessName!=expected_process | table Time, ParentProcessName, NewProcessName"
        ],
        "hunt_steps": [
            "Query process creation logs for anomalies.",
            "Investigate suspicious parent-child process relationships.",
            "Look for parent processes that do not align with known execution paths."
        ],
        "expected_outcomes": [
            "Detection of malicious processes attempting to evade security controls.",
            "Identification of unauthorized privilege escalation attempts."
        ],
        "false_positive": "Some administrative tools may create processes with unexpected PPIDs as part of normal operations.",
        "clearing_steps": [
            "Terminate malicious processes.",
            "Investigate and remove any unauthorized process creation mechanisms."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1055 (Process Injection)", "example": "Adversaries may inject code into legitimate processes to manipulate execution."}
        ],
        "watchlist": [
            "Monitor processes launched by unexpected parent processes.",
            "Detect processes running with elevated privileges unexpectedly."
        ],
        "enhancements": [
            "Implement application whitelisting to restrict unauthorized process creation.",
            "Use endpoint protection to detect and block process manipulation techniques."
        ],
        "summary": "Adversaries may manipulate the Parent Process ID (PPID) to make malicious processes appear as if they were spawned by legitimate ones.",
        "remediation": "Investigate anomalous process execution chains and remove unauthorized processes.",
        "improvements": "Enhance logging and monitoring to detect process manipulation techniques more effectively."
    }
