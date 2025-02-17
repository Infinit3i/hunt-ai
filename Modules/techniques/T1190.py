def get_content():
    return {
        "id": "T1190",
        "url_id": "T1190",
        "title": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "data_sources": "Web Logs, Application Logs, Network Traffic Analysis, File Monitoring",
        "protocol": "HTTP, HTTPS, TCP, UDP",
        "os": "Linux, Windows, macOS",
        "objective": "Adversaries may exploit weaknesses in internet-facing applications to gain unauthorized access.",
        "scope": "Monitor public-facing applications for signs of exploitation attempts.",
        "threat_model": "Attackers may leverage unpatched vulnerabilities, misconfigurations, or zero-days in public-facing applications to execute remote code or obtain unauthorized access.",
        "hypothesis": [
            "Are there unusual access patterns targeting public applications?",
            "Are there known CVE exploitation attempts occurring in logs?",
            "Are attackers leveraging remote code execution vulnerabilities?"
        ],
        "tips": [
            "Regularly patch and update all internet-facing applications.",
            "Implement Web Application Firewalls (WAF) to detect and prevent common attacks.",
            "Monitor network and web logs for anomalous access patterns."
        ],
        "log_sources": [
            {"type": "Web Logs", "source": "Apache, Nginx, IIS", "destination": "SIEM"},
            {"type": "Application Logs", "source": "Tomcat, WebSphere", "destination": "SIEM"},
            {"type": "Network Traffic Analysis", "source": "Firewall Logs, IDS/IPS", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "Web Requests", "location": "Access Logs", "identify": "Potential exploit payloads"}
        ],
        "destination_artifacts": [
            {"type": "Shell Access", "location": "/tmp", "identify": "Unexpected web shells or scripts"}
        ],
        "detection_methods": [
            "Monitor for known exploit payload patterns in web logs.",
            "Detect unauthorized file modifications or shell access.",
            "Analyze traffic patterns for unexpected spikes in requests."
        ],
        "apt": ["G0009", "G0010"],
        "spl_query": [
            "index=web_logs status=200 OR status=500 | stats count by src_ip, uri"
        ],
        "hunt_steps": [
            "Analyze web server logs for suspicious activity.",
            "Inspect firewall and IDS logs for exploit attempts.",
            "Review recent application changes and patch levels."
        ],
        "expected_outcomes": [
            "Identified potential exploitation attempts.",
            "Confirmed no suspicious activity and improved baseline monitoring."
        ],
        "false_positive": "Legitimate security scanners may trigger similar patterns.",
        "clearing_steps": [
            "Patch vulnerable applications.",
            "Remove unauthorized files or web shells.",
            "Reconfigure firewall rules to limit exposure."
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1190", "example": "Exploitation of an unpatched web application."}
        ],
        "watchlist": [
            "Monitor for recurring exploit attempts from the same IP.",
            "Track CVE-related attack patterns in logs."
        ],
        "enhancements": [
            "Deploy runtime application self-protection (RASP).",
            "Enable strict input validation and sanitization."
        ],
        "summary": "Exploitation of internet-facing applications to gain unauthorized access.",
        "remediation": "Patch vulnerabilities, enhance monitoring, and restrict access.",
        "improvements": "Regular security assessments and automated vulnerability scanning."
    }
