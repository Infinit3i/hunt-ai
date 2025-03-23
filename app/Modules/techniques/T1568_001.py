def get_content():
    return {
        "id": "T1568.001",
        "url_id": "T1568/001",
        "title": "Dynamic Resolution: Fast Flux DNS",
        "description": "Adversaries may use Fast Flux DNS to hide a command and control channel behind an array of rapidly changing IP addresses linked to a single domain resolution.",
        "tags": ["fast flux", "dns", "c2", "dynamic resolution"],
        "tactic": "Command and Control",
        "protocol": "DNS",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Compare TTL values of suspicious domains with known fast flux patterns.",
            "Track IP churn rate for a given domain.",
            "Collaborate with ISPs and registrars for detection assistance."
        ],
        "data_sources": "Network Traffic: Network Connection Creation, Network Traffic: Network Traffic Flow",
        "log_sources": [
            {"type": "Network Traffic", "source": "Network Traffic", "destination": "Network Traffic"},
            {"type": "Network Connection", "source": "Network Traffic", "destination": "Network Traffic"}
        ],
        "source_artifacts": [
            {"type": "DNS Request", "location": "Local DNS Resolver", "identify": "Rapid IP rotation on single domain"}
        ],
        "destination_artifacts": [
            {"type": "C2 Channel", "location": "DNS Answer Section", "identify": "Short TTL records with varying IPs"}
        ],
        "detection_methods": [
            "DNS TTL analysis",
            "IP rotation frequency analysis",
            "Anomaly-based domain traffic analysis"
        ],
        "apt": [
            "APT10", "Gamaredon", "TA505", "njRAT", "Gh0stRAT"
        ],
        "spl_query": [
            "index=dns sourcetype=dns_logs\n| stats dc(answer) as unique_ips by query\n| where unique_ips > 10"
        ],
        "hunt_steps": [
            "Identify domains with a high number of unique IP addresses over time.",
            "Investigate domains with abnormally short TTL values.",
            "Trace subsequent traffic to identify beaconing patterns or payload delivery."
        ],
        "expected_outcomes": [
            "Detection of domains used in fast flux infrastructure",
            "Uncovering of resilient C2 channels using frequent IP shifting"
        ],
        "false_positive": "CDN and legitimate dynamic DNS services may show similar behavior with short TTL and changing IPs.",
        "clearing_steps": [
            "Block fast flux domains and associated IP addresses at DNS and firewall layers.",
            "Investigate infected hosts and remove persistence mechanisms."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1071.004", "example": "C2 over DNS"},
            {"tactic": "Command and Control", "technique": "T1090.002", "example": "External Proxy"}
        ],
        "watchlist": [
            "Domains with frequent IP changes",
            "DNS responses with TTL < 300 seconds"
        ],
        "enhancements": [
            "Use passive DNS to analyze IP churn over time.",
            "Integrate with DGA and C2 reputation feeds."
        ],
        "summary": "Fast Flux DNS enables adversaries to obscure the true location of their C2 infrastructure by frequently changing IPs tied to a single domain, often leveraging short TTL values to rapidly rotate endpoints.",
        "remediation": "Use DNS sinkholes, blocklists, and leverage registrar partnerships to take down fast flux domains. Continuously monitor DNS behavior across the network.",
        "improvements": "Implement automated detection of flux behavior using entropy, TTL, and IP frequency metrics with historical analysis."
    }
