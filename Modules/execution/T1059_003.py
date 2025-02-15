def get_content():
    return {
        "id": "T1059.003",
        "url_id": "T1059/003",
        "title": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution",
        "data_sources": "Process Monitoring, Command-Line Logging, Windows Event Logs, Sysmon",
        "protocol": "CLI",
        "os": "Windows",
        "objective": "Detect and mitigate malicious usage of the Windows Command Shell for execution of unauthorized commands or scripts.",
        "scope": "Monitor command-line activity for suspicious execution patterns, unauthorized script execution, and potential abuse of built-in system utilities.",
        "threat_model": "Adversaries may use the Windows Command Shell to execute malicious commands, scripts, and binaries to establish persistence, escalate privileges, or move laterally.",
        "hypothesis": [
            "Are there unauthorized command executions occurring on critical systems?",
            "Are there command-line activities deviating from normal usage patterns?",
            "Are built-in utilities like cmd.exe being abused for lateral movement or privilege escalation?"
        ],
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
        "spl_query": ["index=windows sourcetype=WinEventLog EventCode=4688 Image=""C:\\Windows\\System32\\cmd.exe"" | stats count by ParentImage, CommandLine, User"],
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
