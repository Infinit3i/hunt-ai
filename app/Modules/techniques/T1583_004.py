# attack_technique_T1583_004.py

def get_content():
    return {
        "id": "T1583.004",  
        "url_id": "T1583/004",  
        "title": "Acquire Infrastructure: Server",  
        "description": "Adversaries may buy, lease, or rent physical servers to stage and execute cyber operations such as phishing, drive-by compromise, or command and control.",  
        "tags": [
            "server acquisition", "cybercriminal infrastructure", "command and control servers", 
            "malicious hosting", "dedicated server abuse", "cloud server exploitation", 
            "threat actor infrastructure", "dark web hosting", "cyber threat intelligence"
        ],  
        "tactic": "Resource Development",  
        "protocol": "HTTP, HTTPS, SSH, RDP",  
        "os": ["General"],  
        "tips": [
            "Monitor server hosting services for sudden spikes in new registrations.",
            "Use internet scanning techniques to detect adversary-controlled servers.",
            "Track services listening, SSL/TLS certificates, and other infrastructure identifiers."
        ],  
        "data_sources": [
            "Internet Scan: Response Content", "Internet Scan: Response Metadata", "Threat Intelligence Feeds"
        ],  
        "log_sources": [
            {"type": "Network Traffic", "source": "Suspicious Server Communications", "destination": "SIEM"},
            {"type": "Threat Intelligence", "source": "Known Malicious Server Hosts", "destination": "Threat Hunting Platform"},
            {"type": "Internet Scan", "source": "Newly Registered Server Infrastructure", "destination": "SOC"}
        ],
        "source_artifacts": [
            {"type": "Log File", "location": "/var/log/network_traffic.log", "identify": "Malicious Server Communications"}
        ],
        "destination_artifacts": [
            {"type": "Threat Intelligence", "location": "Adversary-Controlled Server Hosts", "identify": "Malicious Hosting Services"}
        ],
        "detection_methods": [
            "Monitor for newly provisioned servers that match known adversary infrastructure.",
            "Analyze internet scan data for common adversary hosting patterns."
        ],
        "apt": ["Earth Lusca", "Gallium", "SocGholish Operators", "Night Dragon"],  
        "spl_query": [
            "index=network_traffic source=/var/log/network_traffic.log \"Suspicious Server Communication\"\n| table _time, Source_IP, Destination_IP, SSL_Cert"
        ],  
        "hunt_steps": [
            "Identify servers acquired by adversaries for command and control.",
            "Monitor cloud hosting services for patterns indicating malicious infrastructure.",
            "Investigate new server deployments associated with phishing or malware distribution."
        ],  
        "expected_outcomes": [
            "Detection of adversary-controlled infrastructure before active exploitation.",
            "Proactive identification of malicious servers hosting phishing, malware, or C2 operations."
        ],  
        "false_positive": "Legitimate companies deploying cloud or dedicated servers for business operations.",  
        "clearing_steps": [
            "Blacklist known malicious hosting providers and infrastructure.",
            "Engage with server hosting companies to identify and remove adversary-controlled infrastructure."
        ],  
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "Acquire Infrastructure - Server", "example": "Leasing servers to establish a command and control network."}
        ],  
        "watchlist": [
            "Newly registered servers linked to threat actor activities.",
            "Hosting providers frequently exploited by cybercriminals."
        ],  
        "enhancements": [
            "Enable automated internet scans for identifying new adversary infrastructure.",
            "Use AI-driven analysis to track patterns in malicious server provisioning."
        ],  
        "summary": "Adversaries acquire servers to stage cyber operations, host phishing campaigns, distribute malware, and establish command and control.",  
        "remediation": "Monitor hosting services, analyze internet scan data, and employ network filtering to block adversary-controlled servers.",  
        "improvements": "Enhance server tracking with real-time internet scanning and proactive infrastructure monitoring services."  
    }
