def get_content():
    return {
        "id": "T1548.002",
        "url_id": "1548/002",
        "title": "Abuse Elevation Control Mechanism: Bypass User Account Control",
        "description": "Adversaries may bypass UAC mechanisms to elevate process privileges on a system. Windows User Account Control (UAC) allows a program to elevate its privileges (tracked as integrity levels ranging from low to high) to perform a task under administrator-level permissions, possibly by prompting the user for confirmation.",
        "tags": ["Privilege Escalation", "Defense Evasion", "UAC Bypass"],
        "tactic": "Defense Evasion, Privilege Escalation",
        "protocol": "Windows API",
        "os": "Windows",
        "tips": [
            "Monitor process API calls for behavior indicative of Process Injection.",
            "Detect unusual loaded DLLs through DLL Search Order Hijacking.",
            "Analyze registry modifications targeting UAC bypass techniques.",
        ],
        "data_sources": "Command: Command Execution, Process: Process Creation, Process: Process Metadata, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "Command", "source": "Process Execution Logs", "destination": "Windows Security Logs"},
            {"type": "Process Creation", "source": "Sysmon Event ID 1", "destination": "SIEM"},
            {"type": "Windows Registry", "source": "Registry Modification Logs", "destination": "SIEM"},
        ],
        "source_artifacts": [
            {"type": "Registry Key", "location": "HKEY_CURRENT_USER\\Software\\Classes\\mscfile\\shell\\open\\command", "identify": "Modified for UAC bypass"},
            {"type": "Process Execution", "location": "eventvwr.exe", "identify": "Executed with elevated privileges"},
        ],
        "destination_artifacts": [
            {"type": "System Process", "location": "C:\\Windows\\System32\\sdclt.exe", "identify": "Auto-elevated process execution"},
        ],
        "detection_methods": [
            "Monitor registry modifications for unauthorized changes.",
            "Detect execution of known UAC bypass tools (e.g., eventvwr.exe).",
            "Analyze process metadata for suspicious elevation attempts.",
        ],
        "apt": ["Cobalt Group", "FIN6", "MuddyWater", "TA505"],
        "spl_query": [
            "index=security_logs sourcetype=windows_security OR sourcetype=process_creation \n| search process_name IN ('eventvwr.exe', 'sdclt.exe') \n| stats count by src_ip, user, process_name",
        ],
        "hunt_steps": [
            "Analyze process execution logs for UAC bypass indicators.",
            "Check registry modifications related to UAC bypass techniques.",
            "Monitor execution of auto-elevated Windows binaries.",
        ],
        "expected_outcomes": [
            "UAC Bypass Detected: Investigate potential privilege escalation attempts.",
            "No Malicious Activity Found: Enhance detection logic for UAC bypass techniques.",
        ],
        "false_positive": "Some administrative tools may modify registry keys for legitimate purposes.",
        "clearing_steps": [
            "Remove unauthorized registry modifications used for UAC bypass.",
            "Revoke administrator privileges from compromised accounts.",
            "Deploy endpoint monitoring to prevent future privilege escalations.",
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1548.002", "example": "Adversaries bypassing UAC to escalate privileges via eventvwr.exe."},
        ],
        "watchlist": [
            "Monitor execution of eventvwr.exe and sdclt.exe with abnormal parameters.",
            "Detect unusual registry modifications affecting UAC settings.",
            "Track privilege escalations from low to high integrity processes.",
        ],
        "enhancements": [
            "Enable logging for process execution and registry modifications.",
            "Deploy behavioral detection models for privilege escalation attempts.",
        ],
        "summary": "Adversaries may bypass UAC to gain elevated privileges, allowing them to execute commands and manipulate system settings without user approval.",
        "remediation": "Implement least privilege access, monitor registry changes, and block execution of known UAC bypass methods.",
        "improvements": "Strengthen endpoint monitoring, improve detection models for UAC bypass behavior.",
    }
