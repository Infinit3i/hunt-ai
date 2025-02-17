def get_content():
    return {
        "id": "T1059.001",
        "url_id": "T1059/001",
        "title": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "data_sources": "Process Monitoring, Command-Line Logging, PowerShell Logs, Script Block Logging",
        "protocol": "PowerShell",
        "os": "Windows",
        "objective": "Detect and mitigate malicious PowerShell activity used for execution, automation, or post-exploitation.",
        "scope": "Monitor PowerShell command execution for anomalies, detect script-based threats, and analyze malicious PowerShell payloads.",
        "threat_model": "Adversaries use PowerShell for malicious execution, automation, reconnaissance, and payload delivery.",
        "hypothesis": [
            "Are there unauthorized PowerShell script executions?",
            "Is PowerShell being used for credential dumping or lateral movement?",
            "Are there obfuscated or encoded PowerShell commands being executed?"
        ],
        "log_sources": [
            {"type": "Process Execution", "source": "Sysmon (Event ID 1)"},
            {"type": "Command-Line Logging", "source": "Windows Event ID 4688"},
            {"type": "PowerShell Script Execution", "source": "Event ID 4104, 4103"},
            {"type": "Endpoint Security Logs", "source": "CrowdStrike, Defender ATP"}
        ],
        "detection_methods": [
            "Monitor PowerShell command-line parameters for encoded or obfuscated commands.",
            "Detect execution of suspicious PowerShell scripts from untrusted sources.",
            "Analyze script block logging for malicious behavior.",
            "Identify persistent PowerShell usage across multiple hosts."
        ],
        "spl_query": ["index=windows EventCode=4104 OR EventCode=4688 CommandLine=*PowerShell* | stats count by User, CommandLine, ComputerName"],
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
