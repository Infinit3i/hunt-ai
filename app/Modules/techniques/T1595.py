# attack_technique_T1595.py

def get_content():
    return {
        "id": "T1595",  
        "url_id": "T1595",  
        "title": "Active Scanning",  
        "description": "Adversaries may conduct active network scans to gather intelligence on victim infrastructure, identifying vulnerabilities and potential attack vectors.",  
        "tags": [
            "active scanning", "network reconnaissance", "port scanning", "fingerprinting",
            "ICMP scanning", "banner grabbing", "network enumeration", "OS fingerprinting",
            "adversary reconnaissance", "cyber threat intelligence"
        ],  
        "tactic": "Reconnaissance",  
        "protocol": "ICMP, TCP, UDP, HTTP, HTTPS",  
        "os": ["General"],  
        "tips": [
            "Monitor network traffic for unusual scanning patterns and large volumes of requests.",
            "Track anomalies in ICMP, TCP, and UDP requests that indicate scanning activity.",
            "Use threat intelligence feeds to correlate scanning behavior with known adversary activity."
        ],  
        "data_sources": [
            "Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow", "Threat Intelligence Feeds"
        ],  
        "log_sources": [
            {"type": "Network Traffic", "source": "Suspicious Scanning Activity", "destination": "SIEM"},
            {"type": "Threat Intelligence", "source": "Known Malicious IPs Conducting Scans", "destination": "Threat Hunting Platform"},
            {"type": "Firewall Logs", "source": "Blocked or Unusual Connection Attempts", "destination": "SOC"}
        ],
        "source_artifacts": [
            {"type": "Log File", "location": "/var/log/network_scan.log", "identify": "Active Scanning Indicators"}
        ],
        "destination_artifacts": [
            {"type": "Threat Intelligence", "location": "Adversary-Controlled Scanning Infrastructure", "identify": "Malicious Reconnaissance Sources"}
        ],
        "detection_methods": [
            "Monitor for excessive connection attempts to multiple ports or hosts.",
            "Analyze network flow data for patterns indicative of reconnaissance activity."
        ],
        "apt": ["TEMP.Veles", "Advanced Persistent Threat (APT) Groups Conducting Reconnaissance"],  
        "spl_query": [
            "index=network_traffic source=/var/log/network_scan.log \"Suspicious Scanning Activity\"\n| table _time, Source_IP, Destination_IP, Scan_Type"
        ],  
        "hunt_steps": [
            "Identify adversary-controlled IP addresses performing scans on your network.",
            "Monitor unusual spikes in network traffic indicative of automated scanning.",
            "Investigate scanning attempts that focus on specific open ports or protocols."
        ],  
        "expected_outcomes": [
            "Detection of adversary reconnaissance activity before exploitation.",
            "Early identification of scanning sources linked to known threats."
        ],  
        "false_positive": "Legitimate vulnerability scanning or network health monitoring activities.",  
        "clearing_steps": [
            "Blacklist known malicious scanning IPs and update firewall rules.",
            "Engage in threat intelligence sharing to track scanning campaigns."
        ],  
        "mitre_mapping": [
            {"tactic": "Reconnaissance", "technique": "Active Scanning", "example": "Conducting network-wide port scanning to identify open services."}
        ],  
        "watchlist": [
            "Known scanning tools such as Nmap, Masscan, and Zmap.",
            "IPs linked to automated reconnaissance and botnet activity."
        ],  
        "enhancements": [
            "Enable automated alerts for network scans originating from untrusted sources.",
            "Use machine learning to distinguish between legitimate and malicious scanning behavior."
        ],  
        "summary": "Adversaries perform active scanning to identify open ports, services, and vulnerabilities within target networks.",  
        "remediation": "Monitor network logs, analyze scanning patterns, and enforce strict firewall policies to mitigate reconnaissance activities.",  
        "improvements": "Enhance network anomaly detection with AI-driven analysis and threat intelligence correlation."  
    }
