def get_content():
    return {
        "id": "T1543",
        "url_id": "T1543",
        "title": "Create or Modify System Process",
        "tactic": "Persistence",
        "data_sources": "Process Monitoring, Windows Event Logs, Sysmon, Registry, File System",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries creating or modifying system processes to establish persistence.",
        "scope": "Monitor process creation and modification activities to identify unauthorized changes to system services.",
        "threat_model": "Adversaries may abuse system processes to maintain access, escalate privileges, or execute malicious payloads.",
        "hypothesis": [
            "Are new or modified system processes behaving suspiciously?",
            "Are unauthorized users modifying critical system services?",
            "Are adversaries using service creation to execute malware?"
        ],
        "log_sources": [
            {"type": "Process Execution Logs", "source": "Sysmon (Event ID 1), Windows Security Logs"},
            {"type": "Registry Modification Logs", "source": "Sysmon (Event ID 13), Windows Event Logs"},
            {"type": "Service Creation Logs", "source": "Windows Event Logs (Event ID 7045)"},
            {"type": "Threat Intelligence Feeds", "source": "VirusTotal, Hybrid Analysis, MISP"}
        ],
        "detection_methods": [
            "Monitor service creation logs for unauthorized modifications.",
            "Detect registry changes related to service configurations.",
            "Correlate process execution with known persistence techniques."
        ],
        "spl_query": "index=windows EventCode=7045 | stats count by ServiceName, ImagePath, User",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1543",
        "hunt_steps": [
            "Run Queries in SIEM: Detect new or modified system services.",
            "Correlate with Threat Intelligence: Investigate suspicious service modifications.",
            "Analyze Process Execution: Identify unusual service behavior.",
            "Investigate Registry and File System Changes: Detect unauthorized modifications.",
            "Validate & Escalate: Confirm malicious activity and escalate if necessary."
        ],
        "expected_outcomes": [
            "Persistence Mechanism Detected: Disable the unauthorized service and investigate further.",
            "No Malicious Activity Found: Improve monitoring rules for system service modifications."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1543 (Create or Modify System Process)", "example": "Adversaries create malicious services for persistence."},
            {"tactic": "Privilege Escalation", "technique": "T1543.003 (Windows Service)", "example": "Attackers modify services to execute privileged commands."}
        ],
        "watchlist": [
            "Monitor new and modified system services.",
            "Flag unauthorized registry edits related to service configurations.",
            "Detect suspicious service executions tied to malware signatures."
        ],
        "enhancements": [
            "Restrict administrative privileges to prevent unauthorized service modifications.",
            "Enable logging and monitoring of service creation and modifications.",
            "Deploy endpoint detection to flag persistence techniques."
        ],
        "summary": "Detect adversaries abusing system processes for persistence.",
        "remediation": "Disable malicious services, revoke unauthorized access, and improve detection rules.",
        "improvements": "Enhance security monitoring for service-related persistence mechanisms."
    }
