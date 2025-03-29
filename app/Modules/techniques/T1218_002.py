def get_content():
    return {
        "id": "T1218.002",
        "url_id": "T1218/002",
        "title": "System Binary Proxy Execution: Control Panel",
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor usage of `control.exe` with command-line arguments pointing to .cpl files.",
            "Inspect registry keys that register custom or unknown Control Panel items.",
            "Analyze any newly dropped or modified .cpl files in user-writable or non-standard directories."
        ],
        "data_sources": "Command Execution, File Creation, Module Load, OS API Execution, Process Creation, Registry Key Modification",
        "log_sources": [
            {"type": "Process Execution", "source": "Windows Event Logs (4688), Sysmon (Event ID 1)", "destination": "SIEM"},
            {"type": "Registry Auditing", "source": "Sysmon Event ID 13, 14", "destination": "SIEM"},
            {"type": "File System Monitoring", "source": "EDR", "destination": "EDR Console"}
        ],
        "source_artifacts": [
            {"type": ".cpl File", "location": "User directories or temp folders", "identify": "Renamed malicious DLLs with .cpl extension"}
        ],
        "destination_artifacts": [
            {"type": "Registry Key", "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\Cpls", "identify": "Unexpected entries registering .cpl payloads"}
        ],
        "detection_methods": [
            "Monitor command-line activity for `control.exe` or `rundll32.exe` executing .cpl files.",
            "Analyze registry for Control Panel registration anomalies.",
            "Scan .cpl files for suspicious code or missing expected exports like `CPlApplet`."
        ],
        "apt": ["G0016", "G0026"],
        "spl_query": [
            "index=windows process_name=control.exe OR process_name=rundll32.exe (command_line=*cpl*) | stats count by user, host, command_line",
            "index=registry EventCode=13 RegistryPath=\"*Control Panel\\\\Cpls*\" | table _time, RegistryPath, Details"
        ],
        "hunt_steps": [
            "Enumerate all .cpl files on endpoints, especially outside System32.",
            "Audit registry for newly registered Control Panel extensions.",
            "Analyze behavior trees where .cpl execution leads to PowerShell, cmd.exe, or LOLBins."
        ],
        "expected_outcomes": [
            "Malicious .cpl executions detected and associated registry modifications identified.",
            "Control Panel abuse pathways closed via detection engineering or policy enforcement."
        ],
        "false_positive": "Legitimate usage of Control Panel .cpl files for system configuration tasks.",
        "clearing_steps": [
            "Remove suspicious .cpl files and associated registry entries.",
            "Reimage affected hosts if backdoors or persistence are confirmed.",
            "Update detection logic to flag newly introduced .cpl abuse vectors."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1218.002 (System Binary Proxy Execution: Control Panel)", "example": "Adversary drops .cpl file and runs it via control.exe or rundll32.exe to execute payload."}
        ],
        "watchlist": [
            "Watch for control.exe invoking unknown or recently modified .cpl files.",
            "Track registry modifications to CPL-related keys for unusual entries."
        ],
        "enhancements": [
            "Apply application control to restrict execution of unknown .cpl files.",
            "Enable registry monitoring on Control Panel registration keys.",
            "Educate users about the risk of double-clicking strange .cpl attachments."
        ],
        "summary": "Adversaries may proxy execution through `control.exe` and .cpl files to evade defenses and application controls by using trusted binaries.",
        "remediation": "Restrict control.exe execution paths, monitor CPL registrations, and enforce digital signature validation where possible.",
        "improvements": "Develop heuristics for abnormal control panel item behavior and incorporate Control Panel abuse into threat modeling.",
        "mitre_version": "16.1"
    }
