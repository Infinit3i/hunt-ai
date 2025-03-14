# attack_technique_T1583_002.py

def get_content():
    return {
        "id": "T1583.002",  
        "url_id": "T1583/002",  
        "title": "Acquire Infrastructure: DNS Server",  
        "description": "Adversaries may configure and run their own DNS servers to control DNS-based command and control (C2) traffic.",  
        "tags": [
            "DNS server control", "custom DNS infrastructure", "C2 over DNS", "DNS hijacking prevention",
            "DNS-based malware", "adversary-controlled servers", "cyber threat actors",
            "stealth command and control", "network security threats"
        ],  
        "tactic": "Resource Development",  
        "protocol": "DNS",  
        "os": ["General"],  
        "tips": [
            "Monitor DNS queries to detect unusual patterns indicative of malicious activity.",
            "Block known adversary-controlled DNS servers through network security policies.",
            "Use DNS logging and monitoring solutions to analyze potential C2 traffic."
        ],  
        "data_sources": [
            "DNS Traffic Analysis", "Network Flow Monitoring", "Threat Intelligence Feeds"
        ],  
        "log_sources": [
            {"type": "DNS Logs", "source": "DNS Query Monitoring", "destination": "SIEM"},
            {"type": "Network Traffic", "source": "Suspicious Outbound DNS Requests", "destination": "SOC"},
            {"type": "Threat Intelligence", "source": "Known Malicious DNS Servers", "destination": "Threat Hunting Platform"}
        ],
        "source_artifacts": [
            {"type": "Log File", "location": "/var/log/dns_queries.log", "identify": "Suspicious DNS Resolutions"}
        ],
        "destination_artifacts": [
            {"type": "Threat Intelligence", "location": "Adversary-Controlled DNS Infrastructure", "identify": "Malicious DNS Resolvers"}
        ],
        "detection_methods": [
            "Analyze DNS traffic for patterns indicative of C2 communication.",
            "Monitor DNS logs for lookups to adversary-controlled domains."
        ],
        "apt": ["Axiom", "Lyceum DNS Threat Actors"],  
        "spl_query": [
            "index=dns source=/var/log/dns_queries.log \"Suspicious DNS Traffic\"\n| table _time, Source_IP, Queried_Domain, Response_Code"
        ],  
        "hunt_steps": [
            "Identify adversary-controlled DNS servers through passive DNS analysis.",
            "Monitor for malware using DNS tunneling as a C2 mechanism.",
            "Investigate unusual spikes in DNS query traffic."
        ],  
        "expected_outcomes": [
            "Detection of adversary-controlled DNS infrastructure.",
            "Mitigation of DNS-based command and control channels."
        ],  
        "false_positive": "Legitimate enterprise DNS resolution services with high query volume.",  
        "clearing_steps": [
            "Blacklist identified adversary DNS servers at the firewall level.",
            "Deploy DNS security solutions to monitor and block suspicious traffic."
        ],  
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "Acquire Infrastructure - DNS Server", "example": "Running a DNS server for stealthy command and control."}
        ],  
        "watchlist": [
            "Newly registered domains used for DNS-based C2.",
            "DNS queries with anomalous response behavior."
        ],  
        "enhancements": [
            "Use machine learning to detect anomalous DNS query patterns.",
            "Enable DNS over HTTPS (DoH) monitoring to identify covert communication."
        ],  
        "summary": "Adversaries may operate their own DNS servers to facilitate malware communication, command and control, and stealthy data exfiltration.",  
        "remediation": "Monitor DNS logs, block suspicious DNS servers, and leverage threat intelligence to detect adversary-controlled infrastructure.",  
        "improvements": "Enhance DNS security measures and deploy anomaly detection for DNS query traffic."  
    }
