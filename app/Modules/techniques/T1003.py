def get_content():
    return {
        "id": "T1003",
        "url_id": "T1003",
        "title": "OS Credential Dumping",
        "tactic": "Credential Access",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "tags": ["Credential Dumping", "Memory Dumping", "SAM Dumping", "LSASS Memory Dumping"],
        "description": "Adversaries may attempt to dump credentials to obtain account information, passwords, and other sensitive details.",
        "tips": [
            "Enable LSASS protection to prevent credential dumping.",
            "Monitor processes interacting with LSASS, SAM, and memory dumps.",
            "Detect unauthorized execution of Mimikatz or similar tools."
        ],
        "data_sources": "Sysmon, Windows Event Logs, Process Monitoring, File Monitoring, Registry, Memory Analysis",
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Security.evtx", "destination": "System.evtx"},
            {"type": "Process Monitoring", "source": "Sysmon Event ID 10 (ProcessAccess)", "destination": "Sysmon.evtx"},
            {"type": "Registry", "source": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "destination": "Registry.evtx"},
            {"type": "Memory Analysis", "source": "Volatility Framework", "destination": "Memory Dump"}
        ],
        "source_artifacts": [
            {"type": "LSASS Memory Dump", "location": "C:\\Windows\\System32\\lsass.exe", "identify": "Unauthorized memory access."}
        ],
        "destination_artifacts": [
            {"type": "SAM Database", "location": "C:\\Windows\\System32\\config\\SAM", "identify": "Unauthorized registry access."}
        ],
        "detection_methods": [
            "Monitor LSASS memory access (Event ID 10 - Sysmon).",
            "Detect execution of credential dumping tools like Mimikatz.",
            "Track unusual registry access to LSA secrets."
        ],
        "apt": ["G0016", "G0035"],
        "spl_query": [
            "index=windows EventCode=4663 ObjectName=*lsass.exe* | table Time, ProcessName, AccessMask, User",
            "index=windows EventCode=10 TargetImage=*lsass.exe* CallTrace=* | table Time, ProcessName, CallTrace"
        ],
        "hunt_steps": [
            "Investigate all processes accessing LSASS memory.",
            "Check for unauthorized access to credential storage locations.",
            "Analyze PowerShell and command-line execution logs for suspicious credential dumping activities."
        ],
        "expected_outcomes": [
            "Credential dumping attempt detected and mitigated.",
            "No malicious activity found, enhancing monitoring rules."
        ],
        "false_positive": "Legitimate security software may access LSASS for monitoring purposes.",
        "clearing_steps": [
            "Terminate unauthorized processes accessing LSASS.",
            "Delete dumped credential files from system directories.",
            "Audit user accounts and reset compromised credentials."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1003.001 (LSASS Memory Dumping)", "example": "Attackers extract credentials from memory."},
            {"tactic": "Credential Access", "technique": "T1003.002 (Security Account Manager)", "example": "Dumping stored credentials from the SAM database."}
        ],
        "watchlist": [
            "Monitor LSASS process access.",
            "Detect tools executing Mimikatz-like behavior.",
            "Investigate unauthorized memory dumps."
        ],
        "enhancements": [
            "Implement Credential Guard to protect credentials in memory.",
            "Apply least privilege principles to sensitive credentials.",
            "Use endpoint security solutions to detect credential dumping attempts."
        ],
        "summary": "OS Credential Dumping is a technique used by adversaries to extract credentials from memory, registry, or system files.",
        "remediation": "Terminate malicious processes, remove unauthorized credential dumps, and enforce system hardening.",
        "improvements": "Enhance endpoint monitoring, implement strong authentication mechanisms, and audit credential usage."
    }
