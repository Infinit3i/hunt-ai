def get_content():
    return {
        "id": "T1070.003",
        "url_id": "T1070/003",
        "title": "Indicator Removal on Host: Clear Command History",
        "tactic": "Defense Evasion",
        "data_sources": "Process Creation Logs, Shell History Logs, Endpoint Logs, Security Monitoring Tools",
        "protocol": "Shell Commands, Local File Manipulation, Log Clearing Mechanisms",
        "os": "Linux, macOS, Windows",
        "objective": "Detect and mitigate adversaries clearing command history to remove evidence of executed commands and evade detection.",
        "scope": "Identify suspicious command history clearing activities that indicate an attempt to disrupt forensic investigations.",
        "threat_model": "Adversaries clear shell history files such as `.bash_history`, `PowerShell history`, or `cmd.exe history` using built-in shell commands to erase forensic evidence of executed commands.",
        "hypothesis": [
            "Are there unauthorized shell history clearing operations on hosts?",
            "Are adversaries leveraging command-line utilities to remove forensic traces?",
            "Is there an increase in history clearing attempts following suspicious activity?"
        ],
        "log_sources": [
            {"type": "Process Creation Logs", "source": "Linux Auditd, Sysmon for Linux, Windows Event Logs (Event ID 4688)"},
            {"type": "Shell History Logs", "source": "~/.bash_history, ~/.zsh_history, Windows PowerShell Transcription Logs"},
            {"type": "Endpoint Logs", "source": "EDR (CrowdStrike, SentinelOne, Carbon Black)"},
            {"type": "Security Monitoring Tools", "source": "SIEM, Host-based IDS Logs"}
        ],
        "detection_methods": [
            "Monitor for execution of known history clearing commands (`history -c`, `rm ~/.bash_history`, `Clear-History`).",
            "Detect suspicious modifications to shell history files.",
            "Identify unauthorized process execution related to history clearing."
        ],
        "spl_query": [
            "index=endpoint sourcetype=syslog \n| search command=*history -c* OR command=*rm ~/.bash_history* OR command=*Clear-History* \n| stats count by host, user, command"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify command history clearing activity.",
            "Analyze Process Creation Logs: Detect anomalies in shell history deletion behavior.",
            "Monitor for Unauthorized History Clearing: Identify use of `history -c`, `rm`, or `Clear-History` commands.",
            "Correlate with Threat Intelligence: Compare with known defense evasion techniques.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Command History Clearing Detected: Block unauthorized history clearing attempts and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for command history clearing-based defense evasion techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1070.003 (Clear Command History)", "example": "Adversaries using `history -c` to delete shell history."},
            {"tactic": "Execution", "technique": "T1059 (Command and Scripting Interpreter)", "example": "Malware executing scripts while erasing execution traces."}
        ],
        "watchlist": [
            "Flag unexpected executions of history clearing commands.",
            "Monitor for anomalies in command history deletion activities.",
            "Detect unauthorized modifications to shell history logs."
        ],
        "enhancements": [
            "Deploy file integrity monitoring to detect unauthorized modifications to shell history files.",
            "Implement behavioral analytics to detect abnormal history clearing activities.",
            "Improve correlation between command history clearing activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious command history clearing activity and affected systems.",
        "remediation": "Block unauthorized history modifications, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of command history clearing-based defense evasion techniques."
    }
