def get_content():
    return {
        "id": "T1135",
        "url_id": "T1135",
        "title": "Network Share Discovery",
        "tactic": "Discovery",
        "data_sources": "File Monitoring, Process Monitoring, Network Traffic, Windows Event Logs",
        "protocol": "SMB, NFS, CIFS",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries attempting to discover shared network resources to identify potential targets for lateral movement or data exfiltration.",
        "scope": "Monitor system and network logs for enumeration of shared drives, directories, or mounted network resources.",
        "threat_model": "Adversaries may attempt to identify network shares to access sensitive data or use them as a means to move laterally within an environment.",
        "hypothesis": [
            "Are there processes or users performing unexpected network share enumeration?",
            "Are multiple network shares being accessed in a short timeframe?",
            "Is there unusual SMB traffic indicating unauthorized discovery attempts?"
        ],
        "log_sources": [
            {"type": "File Access Logs", "source": "Windows Security Logs (Event ID 5140 - Network Share Access), Sysmon (Event ID 11 - File Creation)"},
            {"type": "Process Execution Logs", "source": "Sysmon (Event ID 1 - Process Creation), Windows Event Logs"},
            {"type": "Network Traffic Analysis", "source": "Zeek (Bro), Suricata, Firewall Logs"},
            {"type": "Command Execution Logs", "source": "PowerShell Logging (Event ID 4104), Bash History"}
        ],
        "detection_methods": [
            "Monitor for execution of commands commonly used for network share discovery (e.g., `net view`, `Get-SmbShare`, `smbclient -L`).",
            "Detect abnormal access to shared directories, especially from non-admin accounts.",
            "Identify excessive SMB or NFS requests in a short period, which may indicate scanning or enumeration.",
            "Correlate unusual access attempts with known attack patterns and threat intelligence sources."
        ],
        "spl_query": ["index=network sourcetype=firewall OR sourcetype=smb_logs | stats count by src_ip, dest_ip, share_name | where count > 20",],
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1135",
        "hunt_steps": [
            "Run queries in SIEM to detect mass network share enumeration activities.",
            "Analyze process execution logs to identify suspicious use of network discovery tools.",
            "Correlate access patterns with user activity logs to identify unauthorized access attempts.",
            "Investigate processes interacting with multiple network shares in a short timeframe.",
            "Validate findings and escalate to Incident Response if needed."
        ],
        "expected_outcomes": [
            "Network share enumeration detected: Investigate source process and user account for further suspicious activity.",
            "No malicious activity found: Improve baseline detection rules and refine false positive filtering."
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1135 (Network Share Discovery)", "example": "Adversary scans for accessible network shares to identify targets for data theft or lateral movement"}
        ],
        "watchlist": [
            "Monitor excessive network share access from non-admin accounts.",
            "Track execution of `net view`, `smbclient -L`, `Get-SmbShare`, or similar network discovery commands.",
            "Flag unusual spikes in SMB, NFS, or CIFS traffic indicative of scanning behavior."
        ],
        "enhancements": [
            "Enable detailed logging of network share access events.",
            "Restrict network share access using least privilege principles.",
            "Use behavioral analytics to detect abnormal network share enumeration patterns."
        ],
        "summary": "Monitor and mitigate unauthorized attempts to enumerate network shares within an environment.",
        "remediation": "Investigate unauthorized network share access attempts, enforce access controls, and implement anomaly detection.",
        "improvements": "Enhance detection capabilities with machine learning models and behavior-based analytics."
    }
