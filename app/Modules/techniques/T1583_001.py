# attack_technique_T1583_001.py

def get_content():
    return {
        "id": "T1583.001",  
        "url_id": "T1583/001",  
        "title": "Acquire Infrastructure: Domains",  
        "description": "Adversaries may acquire domains to support phishing, drive-by compromise, or command and control (C2) operations.",  
        "tags": [
            "domain acquisition", "malicious domains", "typosquatting", "homograph attacks",
            "phishing domains", "command and control infrastructure", "domain fronting",
            "threat actor domains", "expired domain repurposing", "cyber threat intelligence"
        ],  
        "tactic": "Resource Development",  
        "protocol": "DNS, HTTP, HTTPS",  
        "os": ["General"],  
        "tips": [
            "Monitor newly registered domains for similarities to legitimate ones.",
            "Use WHOIS and passive DNS analysis to track adversary domain registrations.",
            "Detect domains with unusual TLDs or homoglyph-based typosquatting."
        ],  
        "data_sources": [
            "Domain Registration Logs", "Passive DNS Monitoring", "Threat Intelligence Feeds"
        ],  
        "log_sources": [
            {"type": "Domain Name", "source": "Active DNS Monitoring", "destination": "SIEM"},
            {"type": "Threat Intelligence", "source": "WHOIS Registration Data", "destination": "Threat Hunting Platform"},
            {"type": "DNS Logs", "source": "Malicious Domain Resolution", "destination": "SOC"}
        ],
        "source_artifacts": [
            {"type": "Log File", "location": "/var/log/dns_queries.log", "identify": "Suspect Domain Resolutions"}
        ],
        "destination_artifacts": [
            {"type": "Threat Intelligence", "location": "Adversary-Controlled Domains", "identify": "Malicious Domain Registrations"}
        ],
        "detection_methods": [
            "Track newly registered domains that mimic trusted organizations.",
            "Analyze WHOIS and registrar data for adversary-linked patterns."
        ],
        "apt": ["APT28", "Lazarus Group", "Cobalt Dickens", "UNC3890"],  
        "spl_query": [
            "index=dns source=/var/log/dns_queries.log \"Suspicious Domain Lookup\"\n| table _time, Source_IP, Queried_Domain, TLD, Registrar"
        ],  
        "hunt_steps": [
            "Identify adversary-acquired domains mimicking known organizations.",
            "Monitor for domains using homoglyphs or alternative TLDs.",
            "Investigate newly purchased domains for potential phishing or C2 activity."
        ],  
        "expected_outcomes": [
            "Detection of adversary-owned domains before active exploitation.",
            "Proactive identification of malicious domain infrastructure."
        ],  
        "false_positive": "Legitimate domain registrations for business expansion or rebranding.",  
        "clearing_steps": [
            "Blacklist known adversary-controlled domains.",
            "Engage domain tracking services to detect future malicious registrations."
        ],  
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "Acquire Infrastructure - Domains", "example": "Registering domains for phishing and C2."}
        ],  
        "watchlist": [
            "Newly registered domains similar to high-profile brands.",
            "Expired domains repurposed by adversaries for malicious activities."
        ],  
        "enhancements": [
            "Enable automated alerts for domain registrations matching monitored patterns.",
            "Use AI-driven threat intelligence to track domain-based attack trends."
        ],  
        "summary": "Adversaries acquire domains to support malicious operations, including phishing, malware delivery, and command and control activities.",  
        "remediation": "Monitor domain registrations, analyze passive DNS data, and employ domain filtering to block malicious domains.",  
        "improvements": "Enhance domain tracking with automated alerts and proactive domain monitoring services."  
    }
