def get_content():
    return {
        "id": "T1202",
        "url_id": "T1202",
        "title": "Indirect Command Execution",
        "description": "Adversaries may abuse utilities that allow for command execution to bypass security restrictions that limit the use of command-line interpreters.",
        "tags": ["Defense Evasion", "Command Execution", "Windows", "LOLBin"],
        "tactic": "Defense Evasion",
        "protocol": "Windows",
        "os": "Windows",
        "tips": [
            "Focus on utilities that execute commands indirectly, such as forfiles, pcalua.exe, and scriptrunner.exe.",
            "Use allowlists and group policy restrictions for known LOLBins to reduce exposure.",
            "Investigate unusual parent-child process relationships, especially involving trusted system utilities."
        ],
        "data_sources": "Windows Security, Sysmon, Windows Application, Windows Powershell",
        "log_sources": [
            {"type": "Sysmon", "source": "source machine", "destination": ""},
            {"type": "Windows Security", "source": "source machine", "destination": ""},
            {"type": "Windows Powershell", "source": "source machine", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Sysmon Logs", "location": "%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx", "identify": "Look for Process Create events (Event ID 1) with unusual or LOLBin utilities like forfiles.exe or pcalua.exe"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor process creation events for known indirect execution utilities",
            "Flag unexpected uses of pcalua.exe, forfiles.exe, or scriptrunner.exe",
            "Correlate execution with network connections or file creation"
        ],
        "apt": ["RedCurl", "RevengeRAT"],
        "spl_query": [
            "index=sysmon EventCode=1\n| search Image=*forfiles.exe* OR Image=*pcalua.exe* OR Image=*scriptrunner.exe*\n| stats count by ParentImage, CommandLine, Image, User"
        ],
        "hunt_steps": [
            "Search process creation logs for LOLBin execution",
            "Identify anomalies where utilities spawn command shells or scripts",
            "Cross-reference with known IOCs or hash values of known abuse cases"
        ],
        "expected_outcomes": [
            "Detection of suspicious command executions using trusted utilities",
            "Identification of evasion attempts avoiding cmd.exe or powershell.exe"
        ],
        "false_positive": "System maintenance tasks may use some of these utilities legitimately. Investigate by verifying the parent process, user context, and command line arguments.",
        "clearing_steps": [
            "taskkill /F /IM forfiles.exe",
            "taskkill /F /IM pcalua.exe",
            "taskkill /F /IM scriptrunner.exe",
            "Clear Prefetch entries: del C:\\Windows\\Prefetch\\*.pf",
            "Clear Sysmon logs: wevtutil cl Microsoft-Windows-Sysmon/Operational"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Execution continues through cmd.exe or PowerShell launched from forfiles.exe"}
        ],
        "watchlist": [
            "Execution of forfiles.exe with /c parameter",
            "Unexpected use of pcalua.exe from user profile directories",
            "Network activity post-scriptrunner.exe execution"
        ],
        "enhancements": [
            "Implement endpoint detection rules for forfiles and similar LOLBins",
            "Use application whitelisting (AppLocker or WDAC)",
            "Enrich alerts with parent-child process relationships"
        ],
        "summary": "Adversaries can use legitimate Windows tools to execute commands indirectly, evading detection by avoiding direct use of cmd.exe or powershell.exe. Techniques like forfiles.exe, pcalua.exe, and scriptrunner.exe can help attackers blend in with normal activity.",
        "remediation": "Apply strict controls to script execution policies, monitor for known LOLBin behaviors, and implement behavior-based detection systems.",
        "improvements": "Add behavioral correlation rules for command chaining from indirect execution tools, integrate YARA-based scanning on execution chains.",
        "mitre_version": "16.1"
    }
