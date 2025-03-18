def get_content():
    return {
        "id": "T1059.003",
        "url_id": "T1059/003",
        "title": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution",
        "data_sources": "Process Monitoring, Command-Line Logging, Windows Event Logs, Sysmon",
        "protocol": "CLI",
        "os": "Windows",
        "tips": [
            "Monitor cmd.exe usage for suspicious command-line arguments or unexpected process trees.",
            "Capture and analyze batch files (.bat/.cmd) that appear in unusual directories.",
            "Restrict or disable script execution for non-admin users if not needed.",
            "Baseline legitimate cmd.exe usage to differentiate from malicious activity."
        ],
        "data_sources": "Windows Security, Windows System, Sysmon, EDR telemetry",
        "log_sources": [
            {"type": "Process Monitoring", "source": "Sysmon (Event ID 1 - Process Creation)"},
            {"type": "Command-Line Logging", "source": "Windows Security Logs (Event ID 4688)"},
            {"type": "Windows Event Logs", "source": "Event ID 6005 - System Start"}
        ],
        "detection_methods": [
            "Monitor execution of cmd.exe with suspicious parameters.",
            "Detect abnormal use of command-line scripting for automation or administrative tasks.",
            "Identify execution of commands that disable security controls or alter system configurations."
        ],
        "apt": [
            "APT41",
            "Gamaredon",
            "FIN7",
            "Cobalt Group"
        ],
        "spl_query": [
            '`windows` EventCode=4688 Image=""C:\\Windows\\System32\\cmd.exe" \n| stats count by ParentImage, CommandLine, User',
            "`windows-security` EventCode=4688 CommandLine=*cmd.exe* \n| stats count by Host, AccountName, CommandLine"
            ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify unauthorized command-line executions and suspicious script activity.",
            "Correlate with Threat Intelligence: Validate suspicious command activity against known attack patterns.",
            "Investigate Execution Context: Determine if the executed commands are legitimate or part of an attack chain.",
            "Review Associated Processes: Identify any unusual parent-child process relationships linked to cmd.exe executions.",
            "Validate & Escalate: If malicious activity is detected → Escalate to Incident Response; if a false positive, refine detection rules."
        ],
        "expected_outcomes": [
            "Malicious Command Execution Detected: Block further execution and investigate compromised systems.",
            "No Malicious Activity Found: Improve monitoring rules and refine detection heuristics."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059.003 (Windows Command Shell)", "example": "Adversaries executing commands via cmd.exe to disable security controls."}
        ],
        "watchlist": [
            "Flag unauthorized use of cmd.exe in non-administrative contexts.",
            "Monitor execution of commands altering security settings or network configurations.",
            "Identify scripts executed through the Windows Command Shell that deviate from standard operational patterns."
        ],
        "enhancements": [
            "Implement logging for all command-line activities.",
            "Restrict command prompt usage for non-administrative users.",
            "Enforce application whitelisting to prevent execution of unauthorized scripts and commands."
        ],
        "summary": "Detect and investigate malicious usage of Windows Command Shell.",
        "remediation": "Block unauthorized command executions, restrict cmd.exe usage where necessary, and monitor for command-line abuses.",
        "improvements": "Enhance visibility into command-line activity and integrate behavioral analysis for early threat detection."
    }
