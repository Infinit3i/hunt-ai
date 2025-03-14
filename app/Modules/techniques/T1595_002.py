# attack_technique_T1595_002.py

def get_content():
    return {
        "id": "T1595.002",  
        "url_id": "T1595/002",  
        "title": "Active Scanning: Vulnerability Scanning",  
        "description": "Adversaries may perform vulnerability scans on victim infrastructure to identify weaknesses that can be exploited during an attack.",  
        "tags": [
            "vulnerability scanning", "network reconnaissance", "exploitable vulnerabilities", 
            "adversary reconnaissance", "security misconfigurations", "CVE detection",
            "server banner grabbing", "attack surface mapping", "cyber threat intelligence"
        ],  
        "tactic": "Reconnaissance",  
        "protocol": "ICMP, TCP, UDP, HTTP, HTTPS",  
        "os": ["General"],  
        "tips": [
            "Monitor network traffic for vulnerability scanning patterns and suspicious probing activity.",
            "Track anomalies in HTTP headers, TCP requests, and ICMP responses for scanning signatures.",
            "Use threat intelligence feeds to correlate scanning behavior with known malicious actors."
        ],  
        "data_sources": [
            "Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow", "Threat Intelligence Feeds"
        ],  
        "log_sources": [
            {"type": "Network Traffic", "source": "Suspicious Vulnerability Scanning Activity", "destination": "SIEM"},
            {"type": "Threat Intelligence", "source": "Known Malicious IPs Conducting Scans", "destination": "Threat Hunting Platform"},
            {"type": "Firewall Logs", "source": "Blocked or Unusual Connection Attempts", "destination": "SOC"}
        ],
        "source_artifacts": [
            {"type": "Log File", "location": "/var/log/vulnerability_scan.log", "identify": "Adversary Vulnerability Scanning"}
        ],
        "destination_artifacts": [
            {"type": "Threat Intelligence", "location": "Adversary-Controlled Scanning Infrastructure", "identify": "Malicious Reconnaissance Sources"}
        ],
        "detection_methods": [
            "Monitor for excessive connection attempts to multiple hosts and services.",
            "Analyze network flow data for patterns indicative of vulnerability scanning."
        ],
        "apt": ["APT35", "AQUATIC PANDA", "Berserk Bear", "WinterVivern", "Pawn Storm"],  
        "spl_query": [
            "index=network_traffic source=/var/log/vulnerability_scan.log \"Suspicious Vulnerability Scan\"\n| table _time, Source_IP, Destination_IP, Scan_Type, CVE_ID"
        ],  
        "hunt_steps": [
            "Identify adversary-controlled IP addresses conducting vulnerability scans.",
            "Monitor web server logs for automated banner grabbing and fingerprinting attempts.",
            "Investigate scanning behavior that aligns with publicly known exploits."
        ],  
        "expected_outcomes": [
            "Detection of adversary reconnaissance activity targeting known vulnerabilities.",
            "Early identification of vulnerability scanning sources linked to cyber threats."
        ],  
        "false_positive": "Legitimate security scanning, penetration testing, or vulnerability management activities.",  
        "clearing_steps": [
            "Blacklist known malicious scanning IPs and update firewall rules.",
            "Engage in threat intelligence sharing to track vulnerability scanning campaigns."
        ],  
        "mitre_mapping": [
            {"tactic": "Reconnaissance", "technique": "Active Scanning - Vulnerability Scanning", "example": "Using Nessus, OpenVAS, or Nmap scripts to detect exploitable vulnerabilities."}
        ],  
        "watchlist": [
            "Known vulnerability scanning tools such as Nessus, OpenVAS, Qualys, and Nmap NSE scripts.",
            "IPs linked to automated reconnaissance and vulnerability exploitation campaigns."
        ],  
        "enhancements": [
            "Enable automated alerts for vulnerability scans originating from untrusted sources.",
            "Use machine learning to distinguish between legitimate security scans and adversary reconnaissance."
        ],  
        "summary": "Adversaries scan victim networks to identify exploitable vulnerabilities and misconfigurations in services and applications.",  
        "remediation": "Monitor network logs, analyze scanning patterns, and enforce strict firewall policies to mitigate reconnaissance activities.",  
        "improvements": "Enhance network anomaly detection with AI-driven analysis and threat intelligence correlation for vulnerability scanning activities."  
    }
