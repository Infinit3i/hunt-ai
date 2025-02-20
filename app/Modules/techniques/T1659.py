def get_content():
    return {
        "id": "T1659",
        "url_id": "T1659",
        "title": "Content Injection",
        "tactic": "Defense Evasion",
        "data_sources": "Web Logs, Process Monitoring, File Integrity Monitoring, Network Traffic Analysis",
        "protocol": "HTTP, HTTPS, SMB, FTP",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate unauthorized modifications to web content, scripts, or system files used for persistence or deception.",
        "scope": "Monitor for unauthorized modifications to critical web content, configuration files, and scripts that could indicate adversary presence.",
        "threat_model": "Adversaries may modify website content, system scripts, or application files to inject malicious code, trick users, or establish persistence.",
        "hypothesis": [
            "Are there unexpected modifications to web pages or scripts?",
            "Are attackers injecting malicious payloads into system files for persistence?",
            "Are unauthorized users making changes to content served by a web server?"
        ],
        "tips": [
            "Enable file integrity monitoring (FIM) to detect unauthorized file modifications.",
            "Monitor HTTP response anomalies that may indicate tampering or injection.",
            "Correlate content modifications with user authentication logs to identify insider threats."
        ],
        "log_sources": [
            {"type": "Web Logs", "source": "Apache/Nginx/IIS Logs", "destination": "SIEM"},
            {"type": "File Integrity Monitoring", "source": "OSSEC, Tripwire", "destination": "Security Console"},
            {"type": "Process Monitoring", "source": "Sysmon Event ID 1 (Process Creation)", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "Web Content", "location": "/var/www/html", "identify": "Injected JavaScript, PHP, or HTML modifications"},
            {"type": "System Scripts", "location": "/etc/init.d/, C:\\Windows\\System32\\", "identify": "Modified startup scripts for persistence"}
        ],
        "destination_artifacts": [
            {"type": "Browser Cache", "location": "User's Browser", "identify": "Injected scripts altering content rendering"},
            {"type": "Network Traffic", "location": "SIEM or Firewall Logs", "identify": "Unexpected outbound connections after content modification"}
        ],
        "detection_methods": [
            "Monitor for unauthorized file changes in web directories.",
            "Analyze web server logs for unusual HTTP responses (e.g., HTTP 200 for expected 404 pages).",
            "Detect unauthorized script execution or scheduled tasks modifying content."
        ],
        "apt": [
            "Lazarus Group", "FIN7", "APT32"
        ],
        "spl_query": "index=web_logs (uri=* | file_modification=*) | search unauthorized changes",
        "hunt_steps": [
            "Identify recent modifications to critical web content or system scripts.",
            "Correlate file modifications with recent user authentication events.",
            "Analyze changes for known malicious injection techniques (JavaScript, PHP backdoors, etc.).",
            "If unauthorized content injection is detected → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Malicious Content Injection Detected: Remove unauthorized modifications, restore from backups, and implement monitoring.",
            "No Malicious Activity Found: Improve content monitoring and logging policies."
        ],
        "false_positive": "Legitimate content updates by administrators or scheduled application updates may trigger alerts."
        ,
        "clearing_steps": [
            "Restore modified files from backups.",
            "Terminate unauthorized processes modifying web content.",
            "Implement stricter file permissions to prevent further modifications."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1547.001 (Startup Items)", "example": "Injected scripts persist via startup configurations."},
            {"tactic": "Execution", "technique": "T1059 (Command and Scripting Interpreter)", "example": "Modified content triggers script execution."},
            {"tactic": "Impact", "technique": "T1491 (Defacement)", "example": "Attackers deface content for misinformation or propaganda."}
        ],
        "watchlist": [
            "Monitor unauthorized changes to high-traffic web pages or authentication scripts.",
            "Detect scripts executing unexpectedly in critical directories.",
            "Alert on web content modifications outside of planned update windows."
        ],
        "enhancements": [
            "Implement web application firewalls (WAF) to detect and prevent content injection attacks.",
            "Use strong access controls and multifactor authentication (MFA) for web content updates.",
            "Regularly audit web content and system scripts for unauthorized modifications."
        ],
        "summary": "Content Injection allows adversaries to modify web pages, scripts, or system files to spread malware, deceive users, or maintain persistence.",
        "remediation": "Restore modified content from known good backups, restrict file modification permissions, and implement integrity monitoring.",
        "improvements": "Enhance detection with behavioral analytics and integrate anomaly detection into web logs."
    }
