def get_content():
    return {
        "id": "T1564.011",
        "url_id": "T1564/011",
        "title": "Hide Artifacts: Ignore Process Interrupts",
        "description": "Adversaries may evade detection and prolong execution by launching commands that ignore process interrupt signals. Most operating systems support signals (like `SIGHUP`) that control process behavior, including termination during session disconnection. Utilities like `nohup` (Linux/macOS) or PowerShell's `-ErrorAction SilentlyContinue` (Windows) can allow a process to continue running even after a user logs out or an error occurs. While this doesn't provide persistence like the Trap technique, it enables malicious processes to avoid being terminated under normal system interruption conditions.",
        "tags": ["nohup", "SilentlyContinue", "signal evasion", "hangup protection", "SIGHUP", "ErrorAction"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor long-running processes started with `nohup` or similar flags",
            "Audit PowerShell executions with `-ErrorAction SilentlyContinue`",
            "Correlate session logoff events with background process activity"
        ],
        "data_sources": "Process: Process Creation",
        "log_sources": [
            {"type": "Process", "source": "Sysmon", "destination": ""},
            {"type": "Command", "source": "Bash History or PowerShell Logs", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Command", "location": "Terminal history", "identify": "Use of nohup or shell backgrounding"},
            {"type": "Script", "location": "PowerShell scripts", "identify": "Error suppression with SilentlyContinue"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "Process table", "identify": "Detached or orphaned long-running processes"},
            {"type": "Log", "location": "Sysmon or EDR logs", "identify": "Process started prior to session termination"}
        ],
        "detection_methods": [
            "Monitor for detached processes using `nohup`, `disown`, or backgrounding with `&`",
            "Alert on PowerShell executions that use `-ErrorAction SilentlyContinue`",
            "Correlate user logoff or session close events with lingering active processes"
        ],
        "apt": [
            "StellarParticle", "BPFDoor"
        ],
        "spl_query": [
            "index=sysmon EventCode=1 \n| search CommandLine=\"*nohup*\" OR CommandLine=\"*-ErrorAction SilentlyContinue*\" \n| stats count by CommandLine, ParentImage, User",
            "index=security EventCode=4647 OR EventCode=4634 \n| join user [ search index=sysmon EventCode=1 ] \n| where _time > logoff_time \n| stats count by Image, CommandLine"
        ],
        "hunt_steps": [
            "Query historical logs for suspicious uses of nohup, disown, or backgrounding operators",
            "Cross-reference logoff events with process start times to catch hangup survivors",
            "Use memory analysis tools to spot processes still running after session ends"
        ],
        "expected_outcomes": [
            "Processes discovered running long after user session ends",
            "Suppressed error messages or ignored exit codes in script logs",
            "Detection of misuse of shell and PowerShell commands for evasion"
        ],
        "false_positive": "System administrators may use these flags for legitimate long-running tasks. Context is key — correlate with process ancestry and purpose.",
        "clearing_steps": [
            "Kill background processes not associated with active or scheduled jobs",
            "Revoke script execution privileges for suspicious accounts",
            "Review shell configuration files for nohup misuse"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_commonparameters#erroraction"],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1059", "example": "Using shell command arguments to suppress termination"},
            {"tactic": "Execution", "technique": "T1059.001", "example": "PowerShell with suppressed error outputs"}
        ],
        "watchlist": [
            "PowerShell with `SilentlyContinue` used excessively",
            "Processes that survive across session terminations",
            "Cron jobs or user scripts containing nohup/disown"
        ],
        "enhancements": [
            "Add EDR alerts for use of nohup and SilentlyContinue",
            "Deploy process-tracking tools that persist across user logoff",
            "Use login/logout correlation engines to trace residual execution"
        ],
        "summary": "Attackers may use techniques like `nohup` or suppressed error handling to keep malicious processes running beyond typical session lifecycle boundaries. This offers evasion from user-driven shutdowns or network session termination without requiring full persistence.",
        "remediation": "Audit startup scripts and enforce proper job scheduling policies. Enable strict PowerShell logging with error handling tracing.",
        "improvements": "Integrate runtime memory scanners to identify orphaned and detached processes that outlive user sessions.",
        "mitre_version": "16.1"
    }
