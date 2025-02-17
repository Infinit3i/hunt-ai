def get_content():
    """
    Returns structured content for the Modify Registry technique (T1112).
    """
    return {
        "id": "T1112",
        "url_id": "T1112",
        "title": "Modify Registry",
        "tactic": "Defense Evasion, Persistence",
        "data_sources": "Windows Registry, Windows Event Logs, Sysmon",
        "protocol": "N/A",
        "os": "Windows",
        "objective": "Adversaries modify Windows Registry keys and values to achieve persistence or evade defenses.",
        "scope": "Monitor registry changes that may indicate unauthorized modifications.",
        "threat_model": "Attackers use registry modifications to configure malware persistence, disable security tools, or modify system behaviors.",
        "hypothesis": [
            "Are unauthorized registry changes occurring outside normal administrative activity?",
            "Are registry modifications linked to known malicious processes?",
            "Are attackers disabling security settings via registry changes?"
        ],
        "tips": [
            "Monitor Event ID 4657 (Registry modification detected).",
            "Enable Sysmon Event ID 13 for detailed registry change logging.",
            "Monitor registry paths related to persistence (e.g., Run keys, Winlogon keys)."
        ],
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Security.evtx", "destination": "System.evtx"},
            {"type": "Sysmon", "source": "Event ID 13", "destination": "Registry modifications"},
            {"type": "Windows Registry", "source": "HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER", "destination": "Registry Editor"}
        ],
        "source_artifacts": [
            {"type": "Registry", "location": "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run", "identify": "Persistence mechanisms"},
            {"type": "Registry", "location": "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services", "identify": "Service configuration changes"}
        ],
        "destination_artifacts": [
            {"type": "Registry", "location": "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run", "identify": "User-level persistence mechanisms"}
        ],
        "detection_methods": [
            "Monitor modifications to critical registry paths.",
            "Detect registry changes linked to unauthorized process execution.",
            "Use behavioral analytics to identify unusual registry activity."
        ],
        "apt": ["G0016", "G0045"],
        "spl_query": [
            "index=windows EventCode=4657 | table Time, RegistryKey, User",
            "index=sysmon EventCode=13 | table Time, RegistryPath, ProcessName"
        ],
        "hunt_steps": [
            "Analyze registry modifications from security logs.",
            "Investigate process execution events associated with registry changes.",
            "Identify unauthorized registry persistence mechanisms."
        ],
        "expected_outcomes": [
            "Unauthorized registry modifications detected and mitigated.",
            "No suspicious activity found, refining detection rules."
        ],
        "false_positive": "System administrators and legitimate software may modify registry settings as part of maintenance.",
        "clearing_steps": [
            "reg delete <RegistryKey> /f",
            "Restore registry settings from a known clean state."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1547.001 (Registry Run Keys / Startup Folder)", "example": "Adversaries may use registry keys for persistence."}
        ],
        "watchlist": [
            "Monitor frequent registry modifications by non-administrative users.",
            "Detect registry changes related to known malware families."
        ],
        "enhancements": [
            "Restrict registry modification permissions for non-administrative users.",
            "Enable registry auditing to track unauthorized changes."
        ],
        "summary": "Adversaries modify registry settings to achieve persistence, disable security controls, or evade detection.",
        "remediation": "Revert unauthorized registry changes and enforce security policies to prevent future modifications.",
        "improvements": "Enhance registry monitoring with automated alerting for suspicious modifications."
    }
