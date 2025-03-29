def get_content():
    return {
        "id": "T1218.009",
        "url_id": "T1218/009",
        "title": "System Binary Proxy Execution: Regsvcs/Regasm",
        "tactic": "Defense Evasion",
        "protocol": "Local Execution",
        "os": "Windows",
        "tips": [
            "Watch for use of Regsvcs.exe or Regasm.exe registering DLLs in unexpected paths.",
            "Monitor binaries using [ComRegisterFunction] or [ComUnregisterFunction] attributes.",
            "Establish baselines of known good usage for .NET COM assembly registration."
        ],
        "data_sources": "Command Execution, Process Creation",
        "log_sources": [
            {"type": "Process Creation", "source": "Sysmon (Event ID 1)", "destination": "SIEM"},
            {"type": "Command Execution", "source": "Windows Event Logs (4688)", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "DLL/.NET assembly", "location": "User directories or Public folders", "identify": "Abused with COM registration functions"}
        ],
        "destination_artifacts": [
            {"type": "Registered COM component", "location": "Registry", "identify": "COM keys or CLSID created during registration"}
        ],
        "detection_methods": [
            "Process monitoring of Regsvcs.exe and Regasm.exe command-line arguments.",
            "Correlation of these processes with DLLs in uncommon or writable paths.",
            "Registry auditing to catch unexpected COM class registrations."
        ],
        "apt": ["G0006", "G1006"],
        "spl_query": [
            "index=windows sourcetype=WinEventLog:Security EventCode=4688 New_Process_Name=*regsvcs.exe* OR *regasm.exe*",
            "index=sysmon EventCode=1 Image=*regsvcs.exe OR *regasm.exe*",
            "index=sysmon EventCode=13 TargetObject=*\\CLSID\\*"
        ],
        "hunt_steps": [
            "Search for executions of regsvcs.exe or regasm.exe in unusual user contexts.",
            "Correlate any DLLs passed into the command for suspicious or unsigned origins.",
            "Check registry for COM entries tied to unknown or unverified assemblies.",
            "Reverse engineer or analyze the .NET assemblies for [ComRegisterFunction] logic.",
            "Determine whether these executions followed phishing or lateral movement activities."
        ],
        "expected_outcomes": [
            "Abuse of .NET registration binaries is detected and prevented.",
            "DLLs leveraging COM attributes for stealthy execution are uncovered.",
            "Environments establish strong baselines for regsvcs/regasm usage."
        ],
        "false_positive": "These utilities are rarely used by non-admin users. However, certain developer or IT workflows may invoke them legitimately.",
        "clearing_steps": [
            "Terminate related regsvcs/regasm processes if malicious.",
            "Delete malicious .NET assemblies from host systems.",
            "Clean registry entries under HKCR\\CLSID\\ associated with rogue COM registrations."
        ],
        "mitre_mapping": [
            {
                "tactic": "Defense Evasion",
                "technique": "T1218.009 (System Binary Proxy Execution: Regsvcs/Regasm)",
                "example": "Malicious DLLs using ComRegisterFunction to execute via regasm.exe or regsvcs.exe"
            }
        ],
        "watchlist": [
            "Monitor any regsvcs.exe or regasm.exe execution outside of known administrative tasks.",
            "Track unsigned or user-dropped .NET DLLs being registered.",
            "Audit registry paths for unexpected COM components or recent additions."
        ],
        "enhancements": [
            "Apply AppLocker/WDAC policies to restrict regsvcs/regasm usage to approved paths.",
            "Use signature enforcement for COM DLLs registered in your environment.",
            "Tag regsvcs.exe and regasm.exe in EDRs for anomaly detection across lateral movement paths."
        ],
        "summary": "Regsvcs.exe and Regasm.exe are legitimate .NET utilities that can be abused to execute arbitrary code using COM registration functions, enabling stealthy defense evasion and application control bypass.",
        "remediation": "Audit and block unapproved uses of regsvcs/regasm. Remove any unauthorized COM registrations and associated binaries.",
        "improvements": "Harden COM registration by limiting DLL execution in writable paths. Improve baseline monitoring for .NET assembly behavior.",
        "mitre_version": "16.1"
    }
