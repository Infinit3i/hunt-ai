def get_content():
    return {
        "id": "T1547",
        "url_id": "T1547",
        "title": "Boot or Logon Autostart Execution",
        "description": (
            "Adversaries may configure system settings to automatically execute a program during system boot or logon"
            " to maintain persistence or gain higher-level privileges on compromised systems."
            " Operating systems may have mechanisms for automatically running a program on system boot or account logon."
            " These mechanisms may include automatically executing programs that are placed in specially designated"
            " directories or are referenced by repositories that store configuration information, such as the Windows Registry."
        ),
        "tags": ["Persistence", "Privilege Escalation", "Windows", "Linux", "macOS"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "Windows, Linux, macOS, Network",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Monitor for additions or modifications of autostart execution mechanisms in the Registry.",
            "Use Sysinternals Autoruns to detect system autostart configuration changes.",
            "Analyze abnormal process behavior and DLL loads by monitoring execution flows."
        ],
        "data_sources": "Command: Command Execution, Driver: Driver Load, File: File Creation, File: File Modification,"
                        "Kernel: Kernel Module Load, Module: Module Load, Process: OS API Execution, Process: Process Creation,"
                        "Windows Registry: Windows Registry Key Creation, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "Registry Monitoring", "source": "Sysmon (Event ID 13 - Registry Modification)"},
            {"type": "File System Monitoring", "source": "Sysmon (Event ID 11 - File Create)"},
            {"type": "Process Execution Logs", "source": "Sysmon (Event ID 1 - Process Creation)"},
            {"type": "Windows Event Logs", "source": "Security Logs (Event ID 4688 - New Process Created)"},
            {"type": "EDR", "source": "CrowdStrike, Defender ATP, Carbon Black"}
        ],
        "detection_methods": [
            "Monitor for changes to common persistence registry keys.",
            "Detect unauthorized file modifications in startup directories.",
            "Identify suspicious processes executing during boot or user login.",
            "Analyze scheduled tasks for anomalous execution patterns."
        ],
        "spl_query": ["index=windows EventCode=4657 RegistryPath=\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*\" | stats count by RegistryPath, ProcessName",],
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1547",
        "hunt_steps": [
            "Run Queries in SIEM: Identify registry modifications, startup folder changes, and scheduled tasks.",
            "Correlate with Threat Intelligence: Check hashes and registry changes against known persistence techniques.",
            "Investigate Process Execution: Analyze suspicious processes executed at boot or logon.",
            "Monitor Scheduled Tasks: Identify unauthorized or unusual task executions.",
            "Validate & Escalate: If persistence is detected, escalate for remediation and containment."
        ],
        "expected_outcomes": [
            "Persistence Mechanism Detected: Remove unauthorized entries and isolate affected systems.",
            "No Malicious Activity Found: Improve detection baselines and enhance monitoring of persistence techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1547 (Boot or Logon Autostart Execution)", "example": "Malware modifying startup registry keys."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Adversaries delete logs to conceal persistence mechanisms."},
            {"tactic": "Privilege Escalation", "technique": "T1068 (Exploiting Privileged Execution)", "example": "Modifications to privileged autostart locations."}
        ],
        "watchlist": [
            "Monitor changes to HKCU\Software\Microsoft\Windows\CurrentVersion\Run.",
            "Detect modifications to startup folders: C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup.",
            "Monitor scheduled task modifications related to user logon events."
        ],
        "enhancements": [
            "Enable process execution monitoring for boot and logon events.",
            "Implement application whitelisting to prevent unauthorized autostart entries.",
            "Restrict user permissions to modify registry autostart keys."
        ],
        "summary": "Document persistence attempts using boot or logon autostart execution methods.",
        "remediation": "Remove unauthorized registry entries, startup folder files, and scheduled tasks.",
        "improvements": "Enhance monitoring of system boot processes and user logon behaviors."
    }
