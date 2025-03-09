def get_content():
    return {
        "id": "T1562.001",
        "url_id": "T1562/001",
        "title": "Defense Evasion: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "data_sources": "Process Creation Logs, Security Monitoring Tools, Registry Monitoring, File Monitoring",
        "protocol": "Windows API, PowerShell, Linux Commands, Registry Edits",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries disabling or modifying security tools to evade detection and maintain persistence.",
        "scope": "Identify unauthorized attempts to disable endpoint protection, modify security configurations, or tamper with logging mechanisms.",
        "threat_model": "Adversaries disable or alter security tools such as antivirus, logging services, and monitoring agents to evade detection and execute malicious actions undetected.",
        "hypothesis": [
            "Are security tools being disabled or modified unexpectedly?",
            "Are adversaries tampering with logging mechanisms to hide their activities?",
            "Is there an increase in unauthorized modifications to security configurations?"
        ],
        "log_sources": [
            {"type": "Process Creation Logs", "source": "Sysmon (Event ID 1, 13), Windows Security Logs (Event ID 4688)"},
            {"type": "Security Monitoring Tools", "source": "SIEM, EDR (CrowdStrike, Defender ATP, Carbon Black)"},
            {"type": "Registry Monitoring", "source": "Windows Event Logs (Event ID 4657)"},
            {"type": "File Monitoring", "source": "Sysmon (Event ID 11), Windows Security Logs (Event ID 4663)"}
        ],
        "detection_methods": [
            "Monitor for processes attempting to stop or disable security services.",
            "Detect unauthorized registry modifications affecting security tools.",
            "Identify deletion or modification of log files and security tool executables."
        ],
        "spl_query": [
            "index=security_logs sourcetype=windows_security OR sourcetype=process_creation \n| search EventID=4688 OR EventID=4657 OR process_name IN ('taskkill', 'wmic', 'sc', 'reg') \n| stats count by src_ip, dest_ip, user, process_name"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify security tool modification attempts.",
            "Analyze Process Creation Logs: Detect unauthorized executions disabling security tools.",
            "Monitor for Unauthorized Registry Edits: Identify changes to security configurations.",
            "Correlate with Threat Intelligence: Compare with known adversary techniques targeting security tools.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Security Tool Modification Detected: Block unauthorized changes and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for security tool tampering techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1562.001 (Disable or Modify Tools)", "example": "Adversaries disabling Windows Defender to execute malware undetected."},
            {"tactic": "Persistence", "technique": "T1547.001 (Registry Run Keys / Startup Folder)", "example": "Attackers modifying security settings via registry keys to maintain persistence."}
        ],
        "watchlist": [
            "Flag processes attempting to stop or disable security services.",
            "Monitor for anomalies in security tool execution and configuration.",
            "Detect unauthorized deletion or modification of log files."
        ],
        "enhancements": [
            "Deploy endpoint protection with tamper resistance.",
            "Implement behavior-based anomaly detection for security tool modifications.",
            "Improve correlation between security tool tampering and known threat actor behaviors."
        ],
        "summary": "Document detected malicious attempts to disable or modify security tools.",
        "remediation": "Block unauthorized security tool modifications, enforce security hardening, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of security tool tampering techniques."
    }
