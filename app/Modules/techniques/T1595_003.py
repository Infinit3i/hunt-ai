def get_content():
    return {
        "id": "T1595.003",  
        "url_id": "T1595/003",  
        "title": "Active Scanning: Wordlist Scanning",  
        "description": "Adversaries may use wordlist-based scanning techniques to discover hidden web directories, cloud storage locations, and administrative portals for reconnaissance and potential exploitation.",  
        "tags": [
            "wordlist scanning", "web directory enumeration", "cloud storage brute-force",
            "hidden file discovery", "web crawling", "cyber threat reconnaissance",
            "admin portal scanning", "bucket enumeration", "exploitation reconnaissance"
        ],  
        "tactic": "Reconnaissance",  
        "protocol": "HTTP, HTTPS, API",  
        "os": ["General"],  
        "tips": [
            "Monitor for excessive HTTP 404 responses or rapid sequential requests to various endpoints.",
            "Detect anomalies in access patterns to sensitive directories and storage locations.",
            "Use threat intelligence feeds to track known adversary scanning tools."
        ],  
        "data_sources": [
            "Network Traffic: Network Traffic Content", "Application Logs", "Cloud Storage Access Logs"
        ],  
        "log_sources": [
            {"type": "Web Server Logs", "source": "Unusual Directory Enumeration", "destination": "SIEM"},
            {"type": "Cloud Access Logs", "source": "Unauthorized Bucket Access Attempts", "destination": "Threat Hunting Platform"},
            {"type": "Network Traffic", "source": "Suspicious Web Crawling Activity", "destination": "SOC"}
        ],
        "source_artifacts": [
            {"type": "Log File", "location": "/var/log/web_scan.log", "identify": "Adversary Web Scanning Activity"}
        ],
        "destination_artifacts": [
            {"type": "Threat Intelligence", "location": "Adversary-Controlled Enumeration Infrastructure", "identify": "Known Scanning IPs and Tools"}
        ],
        "detection_methods": [
            "Monitor web server logs for excessive 404 errors and directory brute-forcing.",
            "Analyze cloud storage access logs for enumeration attempts on non-public buckets."
        ],
        "apt": ["APT41", "Lebanese Cedar", "Advanced Persistent Threat (APT) Groups Conducting Reconnaissance"],  
        "spl_query": [
            "index=web_logs source=/var/log/web_scan.log \"Suspicious Wordlist Scanning\"\n| table _time, Source_IP, Destination_URL, Scan_Type"
        ],  
        "hunt_steps": [
            "Identify adversary-controlled IPs performing large-scale web enumeration.",
            "Monitor for high-frequency requests to common admin panel URLs and hidden files.",
            "Investigate cloud storage access logs for unauthorized bucket enumeration attempts."
        ],  
        "expected_outcomes": [
            "Detection of adversary reconnaissance efforts targeting hidden files and cloud storage.",
            "Early identification of wordlist-based scanning activities linked to cyber threats."
        ],  
        "false_positive": "Legitimate web crawling by search engines or security audits.",  
        "clearing_steps": [
            "Blacklist known malicious scanning IPs and update firewall rules.",
            "Restrict public access to sensitive web directories and cloud storage."
        ],  
        "mitre_mapping": [
            {"tactic": "Reconnaissance", "technique": "Active Scanning - Wordlist Scanning", "example": "Using GoBuster or DirBuster to enumerate hidden directories and admin panels."}
        ],  
        "watchlist": [
            "Known scanning tools such as Dirb, DirBuster, GoBuster, and wfuzz.",
            "IPs linked to automated reconnaissance and web enumeration campaigns."
        ],  
        "enhancements": [
            "Enable automated alerts for rapid directory enumeration attempts.",
            "Use AI-driven analysis to detect anomalies in web access patterns."
        ],  
        "summary": "Adversaries use wordlist-based scanning techniques to discover hidden directories, cloud storage buckets, and sensitive web resources for reconnaissance and potential exploitation.",  
        "remediation": "Monitor web and cloud storage logs, implement access restrictions, and use security controls to block automated enumeration.",  
        "improvements": "Enhance web security monitoring with AI-driven analysis and threat intelligence correlation for detecting automated scanning activities."  
    }
