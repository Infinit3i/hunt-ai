def get_content():
    """
    Returns structured content for PowerShell execution analysis and persistence techniques.
    """
    return {
        "id": "T1059.001",
        "url_id": "T1059/001",
        "title": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "data_sources": "Process Monitoring, Command-Line Logging, PowerShell Logs, Script Block Logging",
        "protocol": "PowerShell",
        "os": "Windows",
        "tips": [
            "Enable PowerShell script block logging for greater visibility.",
            "Monitor changes to PowerShell execution policy via the Registry or command line.",
            "Look for suspicious usage of System.Management.Automation.dll in unusual processes.",
            "Block or restrict PowerShell usage in environments where it is not required."
        ],
        "data_sources": "Windows Powershell, Windows Security, Windows System, Sysmon",
        "log_sources": [
            {"type": "Process Execution", "source": "Sysmon (Event ID 1)", "destination": "Amcache, Shimcache"},
            {"type": "Command-Line Logging", "source": "Windows Event ID 4688", "destination": "Amcache, Shimcache"},
            {"type": "PowerShell Script Execution", "source": "Event ID 4104, 4103", "destination": "Console History, PowerShell Logs"},
            {"type": "Endpoint Security Logs", "source": "CrowdStrike, Defender ATP", "destination": "Security Monitoring Logs"}
        ],
        "source_artifacts": [
            {"type": "AppCompatCache", "location": "SYSTEM Registry Hive", "identify": "Tracks execution of PowerShell executables."},
            {"type": "Console History", "location": "C:\\Users\\<Username>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt", "identify": "Last 4096 PowerShell commands."},
            {"type": "ShimCache", "location": "SYSTEM Registry Hive", "identify": "Records execution of PowerShell executables, including timestamps."},
            {"type": "AmCache", "location": "C:\\Windows\\AppCompat\\Programs\\Amcache.hve", "identify": "Stores metadata for PowerShell.exe execution, including first-time execution timestamps."}
        ],
        "destination_artifacts": [
            {"type": "Registry Modification", "location": "HKEY_CURRENT_USER\\Software\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell", "identify": "Possible policy changes to execution settings."}
        ],
        "detection_methods": [
            "Monitor PowerShell command-line parameters for encoded or obfuscated commands.",
            "Detect execution of suspicious PowerShell scripts from untrusted sources.",
            "Analyze script block logging for malicious behavior.",
            "Identify persistent PowerShell usage across multiple hosts."
        ],
        "apt": ["G0016", "G0032"],  # Example APT groups using PowerShell
        "spl_query": [
            "index=windows EventCode=4104 OR EventCode=4688 CommandLine=*PowerShell* \n| stats count by User, CommandLine, ComputerName",
            # Detect encoded PowerShell commands (base64 encoded payloads)
            "index=windows EventCode=4104 OR EventCode=4688 CommandLine=* -enc * \n| table _time, User, CommandLine, ComputerName",
            # Identify PowerShell script execution from non-standard locations
            "index=windows EventCode=4104 OR EventCode=4688 CommandLine=*PowerShell* NOT (CommandLine=*C:\\Windows\\System32\\WindowsPowerShell*) | table _time, User, CommandLine, ParentProcess, ComputerName"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Detect anomalous PowerShell command execution patterns.",
            "Investigate Scripts: Analyze PowerShell scripts and detect obfuscation techniques.",
            "Monitor System Changes: Identify registry modifications and script-based persistence.",
            "Check for Lateral Movement: Determine if PowerShell is being used for remote execution.",
            "Validate & Escalate: Escalate suspicious PowerShell activity to Incident Response teams."
        ],
        "expected_outcomes": [
            "Malicious PowerShell Activity Detected: Block execution, investigate affected systems, and contain the threat.",
            "No Malicious Activity Found: Improve PowerShell monitoring and refine detection rules."
        ],
        "false_positive": "PowerShell is used by administrators and security teams for automation; investigate deviations from normal usage patterns.",
        "clearing_steps": [
            "Disable PowerShell for non-administrators using GPO.",
            "Set PowerShell execution policy to `Restricted`.",
            "Enable deep script block logging for better visibility."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059.001 (PowerShell)", "example": "Executing malicious PowerShell scripts."},
            {"tactic": "Persistence", "technique": "T1546.013 (Event Triggered Execution - PowerShell Profile)", "example": "Using PowerShell profiles for persistence."},
            {"tactic": "Credential Access", "technique": "T1003.002 (Credential Dumping - LSASS Memory)", "example": "Dumping credentials via PowerShell."}
        ],
        "watchlist": [
            "Flag PowerShell scripts with encoded commands.",
            "Monitor execution of PowerShell commands from unauthorized users.",
            "Detect repeated PowerShell use across multiple endpoints."
        ],
        "enhancements": [
            "Restrict PowerShell execution to administrators only.",
            "Enable PowerShell Constrained Language Mode for non-administrative users.",
            "Deploy AMSI (Antimalware Scan Interface) to inspect PowerShell execution."
        ],
        "summary": "Monitor and mitigate malicious PowerShell usage for execution and post-exploitation.",
        "remediation": "Restrict PowerShell execution policies, block malicious scripts, and enforce logging.",
        "improvements": "Enhance PowerShell monitoring by integrating machine learning-based anomaly detection."
    }



