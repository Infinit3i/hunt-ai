def get_content():
    return {
        "id": "T1547.008",
        "url_id": "1547/008",
        "title": "Boot or Logon Autostart Execution: LSASS Driver",
        "description": "Adversaries may modify or add LSASS drivers to obtain persistence on compromised systems.",
        "tags": ["Persistence", "Privilege Escalation", "Windows"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "Windows",
        "os": "Windows",
        "tips": [
            "Enable LSA Protection to prevent unauthorized modification of LSASS drivers.",
            "Monitor event logs (Event IDs 3033 and 3063) for failed attempts to load LSA plug-ins and drivers.",
            "Utilize Sysinternals Autoruns to examine drivers associated with LSA."
        ],
        "data_sources": "Driver: Driver Load, File: File Creation, File: File Modification, Module: Module Load",
        "log_sources": [
            {"type": "Driver", "source": "LSA Driver Load", "destination": "SIEM"},
            {"type": "File", "source": "Windows System32 Drivers", "destination": "Security Monitoring"}
        ],
        "source_artifacts": [
            {"type": "Driver", "location": "C:\\Windows\\System32\\Drivers", "identify": "Unauthorized LSASS Driver"}
        ],
        "destination_artifacts": [
            {"type": "Log", "location": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "identify": "LSASS Event Logs"}
        ],
        "detection_methods": [
            "Monitor LSA driver loading activity for anomalies.",
            "Correlate unauthorized file modifications with suspicious execution events.",
            "Analyze Sysmon logs for unexpected LSASS driver loads."
        ],
        "apt": ["Pasam", "Wingbird"],
        "spl_query": [
            "index=windows_logs | search EventCode=3033 OR EventCode=3063",
            "index=driver_load | search lsass.exe"
        ],
        "hunt_steps": [
            "Identify newly added LSASS drivers and analyze their source.",
            "Correlate suspicious LSASS driver modifications with recent security events."
        ],
        "expected_outcomes": [
            "Detection of unauthorized LSASS driver modifications.",
            "Identification of adversaries leveraging LSASS driver persistence."
        ],
        "false_positive": "Legitimate security tools may add LSASS-related drivers for protection.",
        "clearing_steps": [
            "Remove unauthorized LSASS driver files from System32\\Drivers.",
            "Enable LSA Protection and Credential Guard to prevent unauthorized changes."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Execution via Malicious LSA Driver"},
            {"tactic": "Privilege Escalation", "technique": "T1068", "example": "Elevating Privileges via LSASS Driver Injection"}
        ],
        "watchlist": [
            "Monitor LSASS driver loads and modifications for anomalies.",
            "Alert on non-standard LSASS driver file paths or unexpected executions."
        ],
        "enhancements": [
            "Implement driver integrity validation to detect tampering.",
            "Restrict modification of LSASS drivers to trusted administrators only."
        ],
        "summary": "Adversaries may modify or install LSASS drivers to maintain persistence and escalate privileges on compromised systems.",
        "remediation": "Enable LSA Protection and restrict unauthorized driver installations.",
        "improvements": "Regularly audit LSASS driver configurations to detect unauthorized modifications."
    }
