def get_content():
    return {
        "id": "T1059",
        "url_id": "T1059",
        "title": "Command & Scripting Interpreter",
        "description": "Adversaries may abuse command-line interfaces and scripting environments to execute malicious code. The command line is often used to interact with operating systems and execute commands, making it a valuable tool for both system administration and adversaries. Attackers can leverage built-in shell environments such as PowerShell, Bash, or CMD to execute payloads, automate malicious activities, and establish persistence.",
        "tags": ["CLI", "PowerShell", "Bash", "CMD", "Script Execution", "Execution"],
        "tactic": "Execution",
        "data_sources": "Process Monitoring, API Logs, Windows Security, Windows PowerShell, Windows Application, Windows System, Sysmon, Zeek, Suricata, Active Directory, Application Log, Cloud Service, Command Execution, File Monitoring, Network Traffic, User Account Activity",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Monitor for suspicious command-line arguments such as Base64 encoded scripts.",
            "Flag execution of scripting engines (PowerShell, Python, Bash) by non-administrative users.",
            "Analyze process execution chains to identify abnormal script activity.",
            "Detect execution of unsigned or untrusted scripts."
        ],
        "log_sources": [
            {"type": "Process Monitoring", "source": "Sysmon Event ID 1 (Process Creation)"},
            {"type": "API Logs", "source": "Windows API Monitoring"},
            {"type": "Windows Security Logs", "source": "Event ID 4688 (Process Creation)"},
            {"type": "File Monitoring", "source": "Monitor script execution paths"},
            {"type": "Network Traffic", "source": "Detect remote command execution over SSH, WinRM, or RDP"}
        ],
        "detection_methods": [
            "Monitor execution of PowerShell, Bash, and CMD instances.",
            "Analyze command-line execution for suspicious parameters.",
            "Detect execution of encoded scripts or commands.",
            "Monitor child processes spawned from script interpreters.",
            "Identify script execution from unexpected locations."
        ],
        "spl_query": [
            'index=endpoint sourcetype=sysmon EventCode=1 \n| stats count by CommandLine',
            'index=windows_logs sourcetype="WinEventLog:Security" EventCode=4688 \n| search CommandLine="*powershell* *-enc*" OR CommandLine="*cmd.exe /c*" OR CommandLine="*python*"',
            'index=linux_logs sourcetype=linux_auditd \n| search command="*bash*" OR command="*sh*" OR command="*python*"'
        ],
        "hunt_steps": [
            "Run SIEM queries to detect suspicious CLI activity.",
            "Investigate users executing PowerShell or Bash scripts.",
            "Identify scripts containing obfuscated or encoded content.",
            "Correlate script execution with network activity.",
            "Monitor process lineage for unexpected script executions."
        ],
        "expected_outcomes": [
            "Identify unauthorized or suspicious command-line execution.",
            "Detect encoded PowerShell or Bash commands.",
            "Uncover attempts to execute scripts from untrusted sources."
        ],
        "false_positive": "System administrators or automation scripts may execute legitimate scripts. Investigate execution context before flagging as malicious.",
        "clearing_steps": [
            "Terminate unauthorized command-line processes.",
            "Disable PowerShell execution for non-administrative users.",
            "Audit and remove unapproved scripts from endpoints.",
            "Implement allow-listing for script execution.",
            "Restrict CLI execution via endpoint protection policies."
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1566 (Phishing)", "example": "Adversaries send malicious emails with links or attachments to trick users into executing payloads."},
            {"tactic": "Defense Evasion", "technique": "T1036 (Masquerading)", "example": "Attackers rename or modify executables to appear legitimate and evade detection."},
            {"tactic": "Persistence", "technique": "T1547 (Boot or Logon Autostart Execution)", "example": "Malicious code is configured to execute automatically upon system startup or user login."},
            {"tactic": "Command and Control", "technique": "T1071 (Application Layer Protocol)", "example": "Attackers use common application protocols like HTTP, HTTPS, or DNS for covert C2 communication."}
        ],
        "watchlist": [
            "Monitor for encoded PowerShell execution using '-enc' flag.",
            "Flag unauthorized execution of scripting engines like Python, Bash, and CMD.",
            "Alert on execution of commands from temporary or user directories.",
            "Identify execution of administrative scripts by non-administrators."
        ],
        "enhancements": [
            "Enable script block logging in PowerShell for visibility.",
            "Use endpoint protection to block execution of untrusted scripts.",
            "Restrict access to scripting environments for non-administrative users.",
            "Implement logging and alerting for command-line execution."
        ],
        "summary": "Monitoring and detecting unauthorized command-line and script execution is critical for preventing malicious payload execution.",
        "remediation": "Disable or restrict unauthorized script execution, investigate flagged events, and remove malicious scripts.",
        "improvements": "Enhance logging for CLI execution, restrict administrative tools, and enforce script execution policies."
    }
