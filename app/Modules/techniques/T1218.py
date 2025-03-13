def get_content():
    return {
        "id": "T1218",
        "url_id": "T1218",
        "title": "System Binary Proxy Execution",
        "tactic": "Defense Evasion",
        "data_sources": "Process monitoring, Command-line monitoring, File monitoring",
        "protocol": "N/A",
        "os": "Windows",
        "data_sources": ["Process Execution", "Command-line Monitoring", "File Monitoring"],
        "tips": [
            "Monitor the execution of `rundll32.exe`, `regsvr32.exe`, and `mshta.exe`.",
            "Analyze command-line arguments for suspicious behavior.",
            "Detect execution of unexpected DLLs or scripts via system binaries."
        ],
        "log_sources": [
            {"type": "Process Execution", "source": "Sysmon Event ID 1", "destination": "Windows Security Logs"},
            {"type": "Command-line Monitoring", "source": "Sysmon Event ID 1", "destination": "SIEM"},
            {"type": "File Monitoring", "source": "Sysmon Event ID 11", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "Prefetch", "location": "C:\\Windows\\Prefetch", "identify": "rundll32.exe, regsvr32.exe, mshta.exe"}
        ],
        "destination_artifacts": [
            {"type": "Execution Logs", "location": "Windows Security Logs", "identify": "Unauthorized execution of system binaries"}
        ],
        "detection_methods": [
            "Monitor execution of trusted binaries for abnormal behavior.",
            "Analyze command-line arguments passed to system binaries.",
            "Detect execution of scripts or DLLs via proxy execution techniques."
        ],
        "apt": ["G0007", "G0032"],
        "spl_query": [
            "index=windows EventCode=1 Image=*\\rundll32.exe \n| table Time, ParentProcess, CommandLine",
            "index=windows EventCode=1 Image=*\\regsvr32.exe \n| table Time, ParentProcess, CommandLine"
        ],
        "hunt_steps": [
            "Identify processes using system binaries with suspicious parameters.",
            "Analyze parent-child process relationships for anomalies.",
            "Investigate any signed binaries executing unknown or unexpected payloads."
        ],
        "expected_outcomes": [
            "Detection of suspicious proxy execution behavior.",
            "Identification of unauthorized binary executions.",
            "Improved visibility into system utilities used for evasion."
        ],
        "false_positive": "Legitimate administrative scripts may use system binaries for execution.",
        "clearing_steps": [
            "Identify and terminate unauthorized proxy execution instances.",
            "Investigate and remove associated malicious payloads.",
            "Apply policies to restrict execution of high-risk system binaries."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1036 (Masquerading)", "example": "Attackers rename system binaries to evade detection."}
        ],
        "watchlist": [
            "Monitor execution of system binaries from unusual locations.",
            "Detect remote execution of trusted system utilities.",
            "Analyze command-line arguments for anomalies."
        ],
        "enhancements": [
            "Implement application whitelisting to block unauthorized execution.",
            "Use endpoint detection tools to monitor system binary execution.",
            "Enforce security policies to restrict high-risk proxy execution techniques."
        ],
        "summary": "Attackers use trusted Windows binaries like `rundll32.exe`, `regsvr32.exe`, and `mshta.exe` to execute malicious code while evading detection.",
        "remediation": "Restrict execution of high-risk system binaries, enforce application whitelisting, and monitor for abnormal execution patterns.",
        "improvements": "Enhance security monitoring for proxy execution techniques and implement endpoint security controls."
    }
