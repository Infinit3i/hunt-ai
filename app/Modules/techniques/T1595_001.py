def get_content():
    return {
        "id": "T1595.001",  
        "url_id": "T1595/001",  
        "title": "Active Scanning: Scanning IP Blocks",  
        "description": "Adversaries may scan victim IP address blocks to identify active hosts, services, and vulnerabilities for further exploitation.",  
        "tags": [
            "IP block scanning", "network reconnaissance", "port scanning", "ICMP probing",
            "banner grabbing", "network enumeration", "adversary reconnaissance", 
            "target discovery", "threat actor scanning", "cyber threat intelligence"
        ],  
        "tactic": "Reconnaissance",  
        "protocol": "ICMP, TCP, UDP, HTTP, HTTPS",  
        "os": ["General"],  
        "tips": [
            "Monitor network traffic for unusual scanning patterns across sequential IP addresses.",
            "Track anomalies in ICMP, TCP, and UDP requests that indicate adversary reconnaissance.",
            "Use threat intelligence feeds to correlate scanning behavior with known malicious actors."
        ],  
        "data_sources": [
            "Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow", "Threat Intelligence Feeds"
        ],  
        "log_sources": [
            {"type": "Network Traffic", "source": "Suspicious IP Block Scanning Activity", "destination": "SIEM"},
            {"type": "Threat Intelligence", "source": "Known Malicious IPs Conducting Scans", "destination": "Threat Hunting Platform"},
            {"type": "Firewall Logs", "source": "Blocked or Unusual Connection Attempts", "destination": "SOC"}
        ],
        "source_artifacts": [
            {"type": "Log File", "location": "/var/log/network_scan.log", "identify": "Active IP Scanning Indicators"}
        ],
        "destination_artifacts": [
            {"type": "Threat Intelligence", "location": "Adversary-Controlled Scanning Infrastructure", "identify": "Malicious Reconnaissance Sources"}
        ],
        "detection_methods": [
            "Monitor for excessive connection attempts to multiple IPs within the same block.",
            "Analyze network flow data for patterns indicative of large-scale scanning."
        ],
        "apt": ["TeamTNT", "GRU29155", "Advanced Persistent Threat (APT) Groups Conducting Reconnaissance"],  
        "spl_query": [
            "index=network_traffic source=/var/log/network_scan.log \"Suspicious IP Block Scanning\"\n| table _time, Source_IP, Destination_IP, Scan_Type"
        ],  
        "hunt_steps": [
            "Identify adversary-controlled IP addresses performing scans across known IP ranges.",
            "Monitor unusual spikes in network traffic indicative of automated reconnaissance.",
            "Investigate scanning attempts that focus on identifying specific network services."
        ],  
        "expected_outcomes": [
            "Detection of adversary reconnaissance activity targeting organizational IP blocks.",
            "Early identification of scanning sources linked to known threats."
        ],  
        "false_positive": "Legitimate security scanning or network health monitoring activities.",  
        "clearing_steps": [
            "Blacklist known malicious scanning IPs and update firewall rules.",
            "Engage in threat intelligence sharing to track scanning campaigns."
        ],  
        "mitre_mapping": [
            {"tactic": "Reconnaissance", "technique": "Active Scanning - Scanning IP Blocks", "example": "Using masscan or Zmap to scan a target organization's IP range."}
        ],  
        "watchlist": [
            "Known scanning tools such as Nmap, Masscan, and Zmap.",
            "IPs linked to automated reconnaissance and botnet activity."
        ],  
        "enhancements": [
            "Enable automated alerts for network scans originating from untrusted sources.",
            "Use machine learning to distinguish between legitimate and malicious scanning behavior."
        ],  
        "summary": "Adversaries perform active scanning across IP blocks to identify active hosts, services, and vulnerabilities for further exploitation.",  
        "remediation": "Monitor network logs, analyze scanning patterns, and enforce strict firewall policies to mitigate reconnaissance activities.",  
        "improvements": "Enhance network anomaly detection with AI-driven analysis and threat intelligence correlation."  
    }
