# attack_technique_T1583.py

def get_content():
    return {
        "id": "T1583",  
        "url_id": "T1583",  
        "title": "Acquire Infrastructure",  
        "description": "Adversaries may buy, lease, or obtain infrastructure, including cloud servers, domains, or botnets, to support malicious operations.",  
        "tags": [
            "cybercriminal infrastructure", "cloud server leasing", "domain registration abuse",
            "adversary botnets", "proxy service exploitation", "malicious hosting", "threat actor infrastructure",
            "command and control servers", "stealth hosting", "dark web infrastructure"
        ],  
        "tactic": "Resource Development",  
        "protocol": "",  
        "os": ["General"],  
        "tips": [
            "Monitor for newly registered domains related to your organization.",
            "Use WHOIS databases to track domain registration patterns.",
            "Analyze internet scans for adversary-controlled infrastructure."
        ],  
        "data_sources": [
            "Domain Registration", "Active DNS", "Passive DNS", "Internet Scan: Response Content", "Internet Scan: Response Metadata"
        ],  
        "log_sources": [
            {"type": "Domain Name", "source": "Active DNS", "destination": "SIEM"},
            {"type": "Network Traffic", "source": "Passive DNS", "destination": "SIEM"},
            {"type": "Threat Intelligence", "source": "WHOIS Registration", "destination": "Threat Hunting Platform"}
        ],
        "source_artifacts": [
            {"type": "Domain Registration", "location": "WHOIS records", "identify": "Recently Registered Malicious Domains"}
        ],
        "destination_artifacts": [
            {"type": "Internet Scan", "location": "C2 Server Discovery", "identify": "Malicious Infrastructure"}
        ],
        "detection_methods": [
            "Monitor for unusual domain registrations related to adversary activity.",
            "Analyze internet scanning results for indicators of threat actor C2 servers."
        ],
        "apt": ["APT43", "StarBlizzard", "Cadet Blizzard", "UNC2165"],  
        "spl_query": [
            "index=threatintel source=whois \"Newly Registered Domains\"\n| table _time, Domain, Registrant, IP_Address"
        ],  
        "hunt_steps": [
            "Identify domains recently registered with suspicious patterns.",
            "Check internet scan results for adversary C2 infrastructure.",
            "Investigate potential proxy service abuse."
        ],  
        "expected_outcomes": [
            "Newly acquired adversary infrastructure detected.",
            "Proactive identification of malicious hosting servers."
        ],  
        "false_positive": "Legitimate companies registering new domains or cloud resources.",  
        "clearing_steps": [
            "Blacklist confirmed malicious domains and infrastructure.",
            "Engage threat intelligence services to track infrastructure movements."
        ],  
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "Acquire Infrastructure", "example": "Leasing servers to establish command and control."}
        ],  
        "watchlist": [
            "New domains linked to threat actor activity.",
            "Cloud hosting services frequently abused by cybercriminals."
        ],  
        "enhancements": [
            "Enable automated tracking of domain registrations tied to adversaries.",
            "Use passive DNS to monitor suspicious infrastructure changes."
        ],  
        "summary": "Threat actors acquire infrastructure such as domains, servers, and proxies to support operations while maintaining stealth.",  
        "remediation": "Monitor domain registrations, analyze network traffic, and use threat intelligence feeds to detect adversary infrastructure.",  
        "improvements": "Implement proactive scanning and tracking of adversary-owned resources."  
    }
