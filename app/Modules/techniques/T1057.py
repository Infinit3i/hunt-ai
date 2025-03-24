def get_content():
    return {
        "id": "T1057",
        "url_id": "T1057",
        "title": "Process Discovery",
        "description": "Adversaries may attempt to get information about running processes on a system. This information can inform further actions, such as privilege escalation or evasion.",
        "tags": ["discovery", "process", "enumeration", "T1057"],
        "tactic": "Discovery",
        "protocol": "",
        "os": "Linux, Network, Windows, macOS",
        "tips": [
            "Correlate process listing activity with unexpected parent-child process relationships.",
            "Use behavioral analytics to detect non-standard enumeration methods."
        ],
        "data_sources": "Command, Process, OS API Execution",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Process: OS API Execution", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Event Logs", "location": "Windows Event Viewer", "identify": "Process start/stop records"},
            {"type": "Process List", "location": "Memory", "identify": "Snapshot of running processes"}
        ],
        "destination_artifacts": [
            {"type": "Event Logs", "location": "Sysmon Logs", "identify": "Process enumeration activity"}
        ],
        "detection_methods": [
            "Monitor execution of process listing utilities like tasklist, ps, Get-Process",
            "Watch for API calls like CreateToolhelp32Snapshot or usage of /proc in Linux"
        ],
        "apt": ["Turla", "APT34", "APT37", "Gamaredon", "APT1", "InvisiMole"],
        "spl_query": [
            "index=main source=*powershell* (Get-Process OR Get-WmiObject)",
            "index=main sourcetype=sysmon EventCode=1 Image=*\\tasklist.exe",
            "index=main sourcetype=sysmon CommandLine=*ps aux*"
        ],
        "hunt_steps": [
            "Identify usage of process enumeration commands across endpoints.",
            "Correlate with lateral movement or privilege escalation events.",
            "Flag access to process enumeration APIs from non-administrative accounts."
        ],
        "expected_outcomes": [
            "Detection of adversarial discovery phase",
            "Alerting on use of suspicious or out-of-place enumeration tools"
        ],
        "false_positive": "Administrators and legitimate IT tools may enumerate processes for monitoring or troubleshooting purposes.",
        "clearing_steps": [
            "Clear bash history (Linux): `cat /dev/null > ~/.bash_history`",
            "Clear PowerShell history (Windows): `Remove-Item (Get-PSReadlineOption).HistorySavePath`",
            "Delete relevant entries in Event Viewer logs or use tools like wevtutil"
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1082", "example": "System Information Discovery after Process Discovery"}
        ],
        "watchlist": [
            "Repeated enumeration from non-standard accounts",
            "Process listing followed by privilege escalation commands"
        ],
        "enhancements": [
            "Implement behavior-based detection using ML to baseline process usage",
            "Integrate Sysmon with EDR for deeper visibility"
        ],
        "summary": "Process discovery allows adversaries to gather information about active software and services, which can guide follow-on actions including lateral movement or privilege escalation.",
        "remediation": "Restrict access to process listing utilities. Monitor for anomalous enumeration behavior. Alert on unusual usage of APIs or commands for discovery.",
        "improvements": "Enable logging on all endpoints for process creation and command line arguments. Train models to recognize normal enumeration behavior across environments.",
        "mitre_version": "16.1"
    }