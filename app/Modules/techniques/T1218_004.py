def get_content():
    return {
        "id": "T1218.004",
        "url_id": "T1218/004",
        "title": "System Binary Proxy Execution: InstallUtil",
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Check for execution of InstallUtil.exe from uncommon directories or user writeable paths.",
            "Flag .NET binaries containing the RunInstaller(true) attribute as potential abuse targets.",
            "Correlate InstallUtil.exe execution with recent file creations or dropped payloads."
        ],
        "data_sources": "Command Execution, Process Creation",
        "log_sources": [
            {"type": "Process Execution", "source": "Sysmon (Event ID 1)", "destination": "SIEM"},
            {"type": "Command Execution", "source": "Windows Event Logs (Event ID 4688)", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": ".NET Binary", "location": "Temp folders, user directories", "identify": "Executable includes RunInstaller(true) attribute and contains custom installer logic."}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "Memory", "identify": "Child process launched via InstallUtil with suspicious binary."}
        ],
        "detection_methods": [
            "Monitor InstallUtil.exe invocations with custom binaries outside of normal installation procedures.",
            "Detect .NET assemblies containing RunInstaller(true) with suspicious or obfuscated logic.",
            "Alert on non-standard command-line usage of InstallUtil."
        ],
        "apt": ["G0126", "G0096"],
        "spl_query": [
            "index=windows process_name=InstallUtil.exe | stats count by user, parent_process, command_line",
            "index=windows EventCode=4688 New_Process_Name=*InstallUtil.exe*"
        ],
        "hunt_steps": [
            "Search for InstallUtil.exe execution from user writeable or temp locations.",
            "Scan .NET binaries for RunInstaller attributes and audit their purpose.",
            "Correlate InstallUtil use with file writes or privilege escalation attempts."
        ],
        "expected_outcomes": [
            "Detection of InstallUtil abuse to execute malicious installer classes.",
            "Identification of stealthy .NET payloads disguised as legitimate components."
        ],
        "false_positive": "Legitimate software installations using custom .NET installers may invoke InstallUtil.exe during setup.",
        "clearing_steps": [
            "Delete unauthorized or malicious .NET installer binaries.",
            "Revoke any compromised accounts used to launch InstallUtil.exe.",
            "Apply AppLocker or WDAC rules to restrict InstallUtil usage."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1218.004 (System Binary Proxy Execution: InstallUtil)", "example": "Execution of malicious installer class via InstallUtil.exe using .NET binary with RunInstaller(true)."}
        ],
        "watchlist": [
            "Alert on InstallUtil.exe launched with external or suspicious binaries.",
            "Watch for execution from uncommon framework versions or locations.",
            "Flag repeated InstallUtil activity by low-privileged users."
        ],
        "enhancements": [
            "Enforce signed .NET assemblies where possible in enterprise environments.",
            "Add detection for known threat actor patterns using InstallUtil abuse.",
            "Enhance forensic playbooks to scan for installer class abuse in .NET payloads."
        ],
        "summary": "InstallUtil.exe is a trusted Windows binary that can be abused to execute malicious .NET assemblies using installer classes with RunInstaller(true).",
        "remediation": "Limit usage of InstallUtil.exe via application control and user education. Audit .NET binaries used with InstallUtil in enterprise environments.",
        "improvements": "Improve detection of installer abuse in .NET assemblies and monitor for anomalous InstallUtil execution chains.",
        "mitre_version": "16.1"
    }
