def get_content():
    return {
        "id": "T1505.005",
        "url_id": "T1505/005",
        "title": "Server Software Component: Terminal Services DLL",
        "description": "Adversaries may abuse the Terminal Services DLL (`termsrv.dll`) to maintain persistent access via Remote Desktop Protocol (RDP). Terminal Services (also known as Remote Desktop Services) use this DLL to manage RDP functionality, and its location is stored in the Windows Registry at `HKLM\\System\\CurrentControlSet\\services\\TermService\\Parameters\\ServiceDll`. By modifying or replacing this DLL, adversaries can achieve persistence, load arbitrary payloads, or enable unauthorized features like concurrent RDP sessions. This technique allows stealthy access and may maintain normal service operation to evade detection.",
        "tags": ["rdp", "persistence", "dll-hijack", "service-dll", "T1505.005"],
        "tactic": "Persistence",
        "protocol": "RDP",
        "os": "Windows",
        "tips": [
            "Verify integrity of `termsrv.dll` regularly.",
            "Monitor registry value of `ServiceDll` under Terminal Services.",
            "Detect suspicious modifications by hashing the DLL on a scheduled basis.",
            "Look for anomalies in module loads within svchost.exe tied to `-k termsvcs`."
        ],
        "data_sources": "Command, File, Module, Process, Windows Registry",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "File", "source": "File Modification", "destination": ""},
            {"type": "Module", "source": "Module Load", "destination": ""},
            {"type": "Process", "source": "Process Creation", "destination": ""},
            {"type": "Windows Registry", "source": "Windows Registry Key Modification", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Registry", "location": "HKLM\\System\\CurrentControlSet\\services\\TermService\\Parameters\\", "identify": "Modified ServiceDll pointing to malicious DLL"},
            {"type": "File", "location": "%SystemRoot%\\System32\\termsrv.dll", "identify": "Tampered or replaced termsrv.dll"},
            {"type": "Process", "location": "svchost.exe -k termsvcs", "identify": "Unexpected DLLs loaded"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "Custom DLL path", "identify": "Payload DLL mimicking legitimate termsrv.dll"},
            {"type": "Registry", "location": "ServiceDll value", "identify": "Pointing to a non-standard path"},
            {"type": "Process", "location": "Child process of svchost.exe", "identify": "Spawned by malicious DLL logic"}
        ],
        "detection_methods": [
            "Monitor changes to the ServiceDll registry key.",
            "Compare hashes of termsrv.dll with baseline versions.",
            "Watch for unexpected module loads within svchost.exe.",
            "Audit execution of reg.exe or PowerShell modifying TermService entries."
        ],
        "apt": [],
        "spl_query": [
            'index=wineventlog sourcetype=WinRegistry\n| search RegistryKeyName="ServiceDll" RegistryPath="*TermService*"\n| stats values(RegistryValueData) by host, _time',
            'index=wineventlog EventCode=4688\n| search ParentImage="*svchost.exe" AND CommandLine="*-k termsvcs*"\n| stats count by CommandLine, host',
            'index=os_logs sourcetype=filesystem\n| search file_path="*termsrv.dll" AND action=modified\n| stats count by file_path, user'
        ],
        "hunt_steps": [
            "Hash the `termsrv.dll` and compare it against known-good values.",
            "Check if the `ServiceDll` registry value has been modified.",
            "Monitor for DLLs loaded into svchost.exe with RDP roles.",
            "Audit for suspicious use of reg.exe or PowerShell setting TermService parameters."
        ],
        "expected_outcomes": [
            "Identification of tampered or replaced DLLs.",
            "Detection of modified registry values pointing to alternate DLL paths.",
            "Prevention of persistent unauthorized RDP access.",
            "Improved hardening of Terminal Services configurations."
        ],
        "false_positive": "Legitimate system administrators may modify Terminal Services for configuration tuning. Verify intent before escalating.",
        "clearing_steps": [
            "Restore legitimate `termsrv.dll` from a clean system or trusted image.",
            "Reset the `ServiceDll` registry key to its default path.",
            "Restart the TermService or reboot the host.",
            "Review system access and rollback any unauthorized user permissions."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1505", "example": "Modifying ServiceDll registry entry for Terminal Services"},
            {"tactic": "Execution", "technique": "T1055.001", "example": "DLL sideloading into svchost.exe"},
            {"tactic": "Privilege Escalation", "technique": "T1543.003", "example": "Service DLL abuse for privileged RDP access"}
        ],
        "watchlist": [
            "Hash mismatches on `termsrv.dll`",
            "Unexpected paths in `ServiceDll` registry values",
            "Unusual activity from svchost.exe with `-k termsvcs`",
            "Concurrent RDP sessions on systems not typically supporting them"
        ],
        "enhancements": [
            "Apply AppLocker or WDAC policies to restrict DLL loading in sensitive directories.",
            "Enable Sysmon Event ID 7 (Image loaded) for DLL load visibility.",
            "Limit write access to system32 folder and RDP registry keys.",
            "Restrict local admin RDP access with group policies."
        ],
        "summary": "Terminal Services DLL hijacking enables stealthy persistence by modifying the `ServiceDll` registry key to point to a malicious or patched `termsrv.dll`. This allows arbitrary code execution while still enabling remote desktop access to the host.",
        "remediation": "Verify and restore the legitimate DLL file, reset registry values, and audit all RDP configurations for unauthorized enhancements. Employ file integrity monitoring on system DLLs.",
        "improvements": "Harden RDP and Terminal Services configurations using GPO, remove unnecessary RDP exposure, and implement layered monitoring for process, registry, and module behaviors.",
        "mitre_version": "16.1"
    }
