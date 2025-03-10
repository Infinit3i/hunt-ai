def get_content():
    return {
        "id": "T1004",
        "url_id": "T1004",
        "title": "Winlogon Helper DLL",
        "tactic": "Persistence",
        "data_sources": "Windows Registry, Sysmon, Windows Security",
        "protocol": "N/A",
        "os": "Windows",
        "tips": [
            "Monitor registry modifications to 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'.",
            "Detect unauthorized DLL files loaded into the Winlogon process.",
            "Check for suspicious modifications in Windows startup DLL configurations."
        ],
        "log_sources": [
            { "type": "Sysmon", "source": "1, 3, 13", "destination": ""},
            {"type": "Windows Security", "source": "4657, 4688", "destination": "" },
            {"type": "Windows Registry", "source": "Windows Registry (Event ID 4657 for Registry Value Modified)", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Registry Key", "location": "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "identify": "Modified DLL path"}
        ],
        "destination_artifacts": [
            {"type": "DLL File", "location": "C:\\Windows\\System32", "identify": "Malicious DLL placed for persistence"}
        ],
        "detection_methods": [
            "Monitor registry modifications to Winlogon keys.",
            "Detect abnormal DLL loads within Winlogon.exe.",
            "Analyze process injection attempts targeting Winlogon."
        ],
        "apt": ["G0016", "G0045"],
        "spl_query": [
            "index=windows EventCode=4657 RegistryPath=HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            '(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1") OR (source="WinEventLog:Security" EventCode="4688") | where (CommandLine LIKE "%Microsoft\Windows NT\CurrentVersion\Winlogon%" AND (CommandLine LIKE "%Userinit%" OR CommandLine LIKE "%Shell%" OR CommandLine LIKE "%Notify%")) AND (CommandLine LIKE "%reg%" OR CommandLine LIKE "%add%" OR CommandLine LIKE "%/d%" OR CommandLine LIKE "%Set-ItemProperty%" OR CommandLine LIKE "%New-ItemProperty%" CommandLine LIKE "%-value%")',
            'source="WinEventLog:Security" EventCode="4657" (ObjectValueName="Userinit" OR ObjectValueName="Shell" OR ObjectValueName="Notify") OR source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" (TargetObject="Userinit" OR TargetObject="Shell" OR TargetObject="*Notify")'
        ],
        "hunt_steps": [
            "Query registry for unexpected modifications to Winlogon keys.",
            "Analyze loaded DLLs in Winlogon.exe for anomalies.",
            "Investigate recent file creations in System32 with suspicious attributes."
        ],
        "expected_outcomes": [
            "Persistence mechanism detected and mitigated.",
            "No suspicious activity found, improving baseline detection."
        ],
        "false_positive": "Legitimate Windows updates or software may modify Winlogon keys.",
        "clearing_steps": [
            "Remove unauthorized registry modifications in HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon.",
            "Delete any unauthorized DLLs placed in System32.",
            "Restart the affected system to ensure changes take effect."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1574.002 (DLL Search Order Hijacking)", "example": "Adversaries hijack DLL search paths for execution."}
        ],
        "watchlist": [
            "Monitor all modifications to Winlogon registry keys.",
            "Detect unexpected DLL file creations in System32.",
            "Investigate suspicious modifications to system startup files."
        ],
        "enhancements": [
            "Enable detailed auditing for registry changes.",
            "Use application whitelisting to prevent unauthorized DLL execution.",
            "Regularly audit system startup configurations."
        ],
        "summary": "Winlogon Helper DLLs allow adversaries to maintain persistence by modifying registry values to load malicious DLLs.",
        "remediation": "Remove unauthorized registry modifications, delete malicious DLLs, and enforce strict startup security policies.",
        "improvements": "Enhance endpoint monitoring, enforce code signing policies, and restrict unauthorized registry modifications."
    }
