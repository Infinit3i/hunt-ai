def get_content():
    return {
        "id": "T1547.012",
        "url_id": "1547/012",
        "title": "Boot or Logon Autostart Execution: Print Processors",
        "description": "Adversaries may abuse print processors to run malicious DLLs during system boot for persistence and/or privilege escalation.",
        "tags": ["Persistence", "Privilege Escalation", "Windows"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "Windows",
        "os": "Windows",
        "tips": [
            "Monitor API calls to 'AddPrintProcessor' and 'GetPrintProcessorDirectory'.",
            "Track new DLLs written to the print processor directory.",
            "Review Registry modifications in 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Environments\\[Windows architecture]\\Print Processors'."
        ],
        "data_sources": "Driver: Driver Load, File: File Creation, Module: Module Load, Process: OS API Execution, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "Process", "source": "API Execution", "destination": "SIEM"},
            {"type": "Registry", "source": "Print Processor Registry Key", "destination": "Security Monitoring"}
        ],
        "source_artifacts": [
            {"type": "DLL", "location": "C:\\Windows\\System32\\spool\\prtprocs\\x64", "identify": "Unauthorized Print Processor DLL"}
        ],
        "destination_artifacts": [
            {"type": "Registry Key", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Environments\\[Windows architecture]\\Print Processors", "identify": "Print Processor Entries"}
        ],
        "detection_methods": [
            "Monitor process API calls related to 'AddPrintProcessor' and 'GetPrintProcessorDirectory'.",
            "Analyze newly created DLLs in the print processor directory for suspicious indicators.",
            "Track Registry modifications to print processor driver values."
        ],
        "apt": ["Gelsemium", "PipeMon", "EarthLusca"],
        "spl_query": [
            "index=windows_registry | search registry_path=\\HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Environments\\*\\Print Processors",
            "index=module_load | search process_name=spoolsv.exe"
        ],
        "hunt_steps": [
            "Identify new print processor drivers added to the Registry.",
            "Check if print processor DLLs are unsigned or located in unexpected directories."
        ],
        "expected_outcomes": [
            "Detection of unauthorized print processor modifications.",
            "Identification of adversaries using print processors for persistence."
        ],
        "false_positive": "Some print management tools may legitimately modify print processor settings.",
        "clearing_steps": [
            "Remove unauthorized entries from 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Environments'.",
            "Delete suspicious DLLs from 'C:\\Windows\\System32\\spool\\prtprocs\\x64'."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Execution via Malicious Print Processor DLL"},
            {"tactic": "Privilege Escalation", "technique": "T1068", "example": "Elevating Privileges via Print Processor Hijacking"}
        ],
        "watchlist": [
            "Monitor for non-standard print processor names in the Registry.",
            "Alert on unexpected DLL loads by 'spoolsv.exe'."
        ],
        "enhancements": [
            "Implement integrity checking for print processor DLLs.",
            "Restrict Registry modifications to print processor settings."
        ],
        "summary": "Adversaries may abuse print processors to run malicious DLLs during system boot for persistence and/or privilege escalation.",
        "remediation": "Restrict unauthorized modifications to print processors and review Registry changes regularly.",
        "improvements": "Regularly audit print processor configurations to detect unauthorized modifications."
    }
