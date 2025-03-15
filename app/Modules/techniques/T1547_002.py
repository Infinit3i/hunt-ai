def get_content():
    return {
        "id": "T1547.002",
        "url_id": "1547/002",
        "title": "Boot or Logon Autostart Execution: Authentication Package",
        "description": (
            "Adversaries may abuse authentication packages to execute DLLs when the system boots."
            " Windows authentication package DLLs are loaded by the Local Security Authority (LSA) process at system start."
            " They provide support for multiple logon processes and multiple security protocols to the operating system."
            " Adversaries can use the autostart mechanism provided by LSA authentication packages for persistence"
            " by placing a reference to a binary in the Windows Registry location"
            " HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\ with the key value of 'Authentication Packages'=<target binary>."
            " The binary will then be executed by the system when the authentication packages are loaded."
        ),
        "tags": ["Persistence", "Privilege Escalation", "Windows"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "Windows",
        "os": "Windows",
        "tips": [
            "Monitor Registry modifications to HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Authentication Packages.",
            "Monitor DLL loads within the LSA process for unauthorized additions.",
            "Enable LSA protection features on Windows 8.1+ to detect unsigned DLLs attempting to load into LSA."
        ],
        "data_sources": "Command: Command Execution, Module: Module Load, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "Windows Registry", "source": "Registry Key Modification", "destination": "SIEM"},
            {"type": "Module", "source": "LSA DLL Loads", "destination": "Security Monitoring"}
        ],
        "source_artifacts": [
            {"type": "Registry Key", "location": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "identify": "Authentication Package Modification"}
        ],
        "destination_artifacts": [
            {"type": "Log", "location": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "identify": "LSA Event Logs"}
        ],
        "detection_methods": [
            "Monitor LSA process activity for unauthorized DLL loading.",
            "Correlate suspicious Registry changes with execution events."
        ],
        "apt": ["Skywiper"],
        "spl_query": [
            "index=windows_registry | search registry_path=\\HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Authentication Packages",
            "index=module_load | search process_name=lsass.exe"
        ],
        "hunt_steps": [
            "Identify new or modified authentication packages in the Registry.",
            "Check if unauthorized DLLs are being loaded by LSA."
        ],
        "expected_outcomes": [
            "Detection of unauthorized authentication package modifications.",
            "Identification of malicious persistence mechanisms using LSA."
        ],
        "false_positive": "Legitimate security software may modify authentication packages for credential management.",
        "clearing_steps": [
            "Remove unauthorized authentication packages from the Registry.",
            "Enable LSA protection to prevent unsigned DLLs from loading."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Execution via LSA DLL Injection"},
            {"tactic": "Privilege Escalation", "technique": "T1068", "example": "Elevating Privileges via LSA Authentication Packages"}
        ],
        "watchlist": [
            "Monitor new or unusual authentication package registrations.",
            "Alert on non-standard DLLs being loaded into LSA."
        ],
        "enhancements": [
            "Implement registry monitoring for LSA modifications.",
            "Enable Windows Defender Credential Guard to secure LSA operations."
        ],
        "summary": "Adversaries may modify authentication packages to execute code during system boot, maintaining persistence and elevating privileges.",
        "remediation": "Restrict modifications to authentication packages using Group Policy.",
        "improvements": "Regularly audit authentication package configurations for unauthorized modifications."
    }
