def get_content():
    return {
        "id": "T1218.003",
        "url_id": "T1218/003",
        "title": "System Binary Proxy Execution: CMSTP",
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Audit execution of `cmstp.exe` with unusual INF files, especially from user-writeable locations.",
            "Detect outbound connections initiated by `cmstp.exe` for remote payload delivery.",
            "Monitor for COM interface abuse using CMSTPLUA and CMLUAUTIL GUIDs."
        ],
        "data_sources": "Command Execution, Network Traffic: Network Connection Creation, Process Creation",
        "log_sources": [
            {"type": "Process Execution", "source": "Sysmon (Event ID 1)", "destination": "SIEM"},
            {"type": "Network Traffic", "source": "Sysmon (Event ID 3)", "destination": "SIEM"},
            {"type": "Process Access", "source": "Sysmon (Event ID 10)", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "INF File", "location": "Dropped in temp or Downloads folder", "identify": "Contains commands to load DLLs or execute PowerShell."}
        ],
        "destination_artifacts": [
            {"type": "Remote COM Interface", "location": "Registry/System memory", "identify": "Auto-elevated interface like CMSTPLUA or CMLUAUTIL triggered via cmstp.exe."}
        ],
        "detection_methods": [
            "Detect process creation where `ParentImage` contains cmstp.exe and child processes launch PowerShell or rundll32.",
            "Identify abnormal command-line arguments passed to cmstp.exe, especially referencing suspicious INF files.",
            "Use Sysmon to detect outbound connections from cmstp.exe or elevated access via COM."
        ],
        "apt": ["G0039", "G0080"],
        "spl_query": [
            "index=windows process_name=cmstp.exe | stats count by user, command_line, parent_process",
            "index=windows EventCode=10 CallTrace=\"*CMLUA.dll*\" OR EventCode=13 TargetObject=\"*CMMGR32.exe*\""
        ],
        "hunt_steps": [
            "Search process logs for cmstp.exe execution patterns with custom INF arguments.",
            "Track network connections initiated by cmstp.exe, flag those reaching external IPs.",
            "Review elevated COM interface access initiated through cmstp."
        ],
        "expected_outcomes": [
            "Detection of CMSTP abuse to proxy execution of remote scripts or DLLs.",
            "Correlated evidence of lateral movement or UAC bypass through COM elevation."
        ],
        "false_positive": "Legitimate deployment of Connection Manager service profiles in enterprise environments.",
        "clearing_steps": [
            "Quarantine malicious INF files used with cmstp.exe.",
            "Block cmstp.exe from executing via application control where unnecessary.",
            "Clean registry traces or COM artifacts associated with malicious usage."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1218.003 (System Binary Proxy Execution: CMSTP)", "example": "Adversary launches cmstp.exe with crafted INF file to execute remote SCT payload."},
            {"tactic": "Privilege Escalation", "technique": "T1548.002 (Bypass User Account Control)", "example": "CMSTP auto-elevates execution using COM interfaces like CMLUAUTIL."}
        ],
        "watchlist": [
            "Alert on cmstp.exe calling out to internet or executing PowerShell scripts.",
            "Watch for registry modifications tied to CMSTP or CMMGR32.",
            "Track anomalies in CMSTP's child processes or elevated behavior."
        ],
        "enhancements": [
            "Apply AppLocker or WDAC rules to restrict CMSTP execution.",
            "Instrument detection for GUIDs related to CMSTP COM interfaces.",
            "Correlate process creation with lateral movement detection logic."
        ],
        "summary": "CMSTP.exe can be abused to proxy execution of malicious content through INF files and auto-elevated COM interfaces, potentially bypassing AppLocker and UAC.",
        "remediation": "Disable CMSTP where unnecessary via Group Policy or AppLocker. Educate staff to avoid executing INF profiles from unknown sources.",
        "improvements": "Enhance visibility into COM-based UAC bypass attempts and implement endpoint rules to detect CMSTP misuse.",
        "mitre_version": "16.1"
    }
