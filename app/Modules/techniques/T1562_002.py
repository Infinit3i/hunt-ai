def get_content():
    return {
        "id": "T1562.002",
        "url_id": "T1562/002",
        "title": "Impair Defenses: Disable Windows Event Logging",
        "description": "Adversaries may disable Windows event logging to reduce visibility into their actions. Windows Event Logs track activities such as logon attempts, process creation, and system changes. By disabling these logs, adversaries can reduce evidence left behind. Methods include stopping the EventLog service, altering registry keys to prevent logging, and modifying audit policies via `auditpol.exe` or `secpol.msc`. Tools like PowerShell, `sc`, and even registry editing can be used to target the EventLog service or associated Autologger keys. Disabling logging may impact all logs (Application, System, Security) or selectively target categories like Account Logon or Logon Events.",
        "tags": ["defense evasion", "event log tampering", "audit policy", "windows registry", "log disabling"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Continuously monitor event service health and critical log activity",
            "Set EventLog service to 'automatic' and enforce start via GPO",
            "Enable Sysmon or other telemetry redundancy where possible"
        ],
        "data_sources": "Command, Process, Script, Windows Registry, Application Log, Sensor Health",
        "log_sources": [
            {"type": "Process", "source": "Command Execution", "destination": ""},
            {"type": "Windows Registry", "source": "Registry Key Modification", "destination": ""},
            {"type": "Application Log", "source": "Event Viewer", "destination": ""},
            {"type": "Sensor Health", "source": "AV/EDR", "destination": ""},
            {"type": "Script", "source": "PowerShell", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Command Line", "location": "auditpol, sc.exe, PowerShell", "identify": "Commands to disable event logging or audit categories"},
            {"type": "Registry", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog", "identify": "Modifications to disable EventLog service"},
            {"type": "Executable", "location": "Invoke-Phant0m.ps1", "identify": "Script used to selectively kill EventLog handles"}
        ],
        "destination_artifacts": [
            {"type": "Windows Service", "location": "EventLog", "identify": "Service stopped or set to disabled"},
            {"type": "Windows Registry", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\*", "identify": "Registry modifications for logging control"},
            {"type": "Windows Registry", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\MiniNT", "identify": "Disables Event Viewer entirely"}
        ],
        "detection_methods": [
            "Monitor command-line usage of `auditpol`, `sc`, `wevtutil`, and PowerShell logging commands",
            "Detect Event ID 1102 (Security log cleared) or 104 (System log cleared)",
            "Monitor for Event ID 7035 indicating service stop",
            "Check for registry key changes related to Autologger or MiniNT"
        ],
        "apt": ["BRONZE UNION", "UNC2452", "Phosphorus"],
        "spl_query": [
            "index=wineventlog EventCode=1102 OR EventCode=104 OR EventCode=7035 \n| stats count by host, EventCode, Message",
            "index=sysmon OR wineventlog process_name IN (auditpol.exe, wevtutil.exe, powershell.exe) \n| search CommandLine IN (*disable*, *clear*, *stop*) \n| stats count by host, user, CommandLine"
        ],
        "hunt_steps": [
            "Query EventLog stop/start events across high-value systems",
            "Identify systems missing expected logging intervals (gaps in sequential record IDs)",
            "Scan registry for unauthorized presence of MiniNT key",
            "Check audit policy baselines against current settings"
        ],
        "expected_outcomes": [
            "Detection of unauthorized audit policy modification or clearing",
            "Identification of tools or users disabling event logs",
            "Corroboration of timeline gaps across logs for forensic analysis"
        ],
        "false_positive": "Legitimate administrators may change audit settings temporarily for troubleshooting. Confirm purpose, user identity, and affected scope.",
        "clearing_steps": [
            "Restart the EventLog service if disabled",
            "Remove malicious MiniNT registry keys and restore service start mode",
            "Reconfigure audit policies using GPO or `auditpol`"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1562.002", "example": "Disable Windows EventLog service to avoid detection"},
            {"tactic": "Defense Evasion", "technique": "T1070.001", "example": "Clear Windows Event Logs using `wevtutil` or `auditpol /clear`"}
        ],
        "watchlist": [
            "Repeated or sudden audit policy disablement across endpoints",
            "Use of known tooling like Invoke-Phant0m, wevtutil, or auditpol in non-admin sessions",
            "Hosts with EventLog service stopped for extended periods"
        ],
        "enhancements": [
            "Implement tamper protection on security service configuration",
            "Send logs to remote SIEM to reduce dependency on local logs",
            "Use Sysmon to mirror important logging and event trails"
        ],
        "summary": "T1562.002 focuses on disabling Windows logging infrastructure to evade detection. Whether targeting audit policies or the EventLog service directly, this technique reduces visibility for defenders and can delay response actions. Defenders should monitor for log manipulation activity and maintain alternate telemetry pipelines.",
        "remediation": "Audit systems regularly for logging integrity. Restore services, enforce auditing via group policy, and centralize logs to prevent single point of failure.",
        "improvements": "Automate alerting for service status changes and track the integrity of audit policies using configuration management tools.",
        "mitre_version": "16.1"
    }
