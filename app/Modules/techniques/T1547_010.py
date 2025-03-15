def get_content():
    return {
        "id": "T1547.010",
        "url_id": "1547/010",
        "title": "Boot or Logon Autostart Execution: Port Monitors",
        "description": "Adversaries may use port monitors to run an adversary-supplied DLL during system boot for persistence or privilege escalation.",
        "tags": ["Persistence", "Privilege Escalation", "Windows"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "Windows",
        "os": "Windows",
        "tips": [
            "Monitor API calls to 'AddMonitor' for suspicious activity.",
            "Track abnormal DLL loads by 'spoolsv.exe' and investigate new or unknown DLLs.",
            "Review Registry modifications in 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors'."
        ],
        "data_sources": "File: File Creation, Module: Module Load, Process: OS API Execution, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "Process", "source": "API Execution", "destination": "SIEM"},
            {"type": "Registry", "source": "Print Monitors Registry Key", "destination": "Security Monitoring"}
        ],
        "source_artifacts": [
            {"type": "DLL", "location": "C:\\Windows\\System32", "identify": "Unauthorized Port Monitor DLL"}
        ],
        "destination_artifacts": [
            {"type": "Registry Key", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors", "identify": "Port Monitor Driver Entries"}
        ],
        "detection_methods": [
            "Monitor process API calls related to 'AddMonitor'.",
            "Analyze newly created DLLs in 'C:\\Windows\\System32' for suspicious indicators.",
            "Track Registry modifications to port monitor driver values."
        ],
        "apt": ["Unknown"],
        "spl_query": [
            "index=windows_registry | search registry_path=\\HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors",
            "index=module_load | search process_name=spoolsv.exe"
        ],
        "hunt_steps": [
            "Identify new port monitor drivers added to the Registry.",
            "Check if port monitor DLLs are unsigned or located in unexpected directories."
        ],
        "expected_outcomes": [
            "Detection of unauthorized port monitor modifications.",
            "Identification of adversaries using port monitors for persistence."
        ],
        "false_positive": "Some print management tools may legitimately modify port monitor settings.",
        "clearing_steps": [
            "Remove unauthorized entries from 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors'.",
            "Delete suspicious DLLs from 'C:\\Windows\\System32'."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Execution via Malicious Port Monitor DLL"},
            {"tactic": "Privilege Escalation", "technique": "T1068", "example": "Elevating Privileges via Port Monitor Hijacking"}
        ],
        "watchlist": [
            "Monitor for non-standard port monitor names in the Registry.",
            "Alert on unexpected DLL loads by 'spoolsv.exe'."
        ],
        "enhancements": [
            "Implement integrity checking for port monitor DLLs.",
            "Restrict Registry modifications to port monitor settings."
        ],
        "summary": "Adversaries may use port monitors to run an adversary-supplied DLL during system boot for persistence or privilege escalation.",
        "remediation": "Restrict unauthorized modifications to port monitors and review Registry changes regularly.",
        "improvements": "Regularly audit print monitor configurations to detect unauthorized modifications."
    }
