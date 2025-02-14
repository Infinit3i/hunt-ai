def get_content():
    return {
        "id": "T1568",
        "url_id": "T1568",
        "title": "Dynamic Resolution",
        "tactic": "Command and Control",
        "data_sources": "DNS, Network Traffic, Endpoint Logs",
        "protocol": "DNS, HTTP, HTTPS",
        "os": "Platform Agnostic",
        "objective": "Detect and investigate adversaries using dynamic resolution techniques to evade detection and establish resilient command-and-control (C2) channels.",
        "scope": "Monitor DNS queries, network traffic, and endpoint logs for signs of dynamic resolution mechanisms used for C2 or malicious infrastructure resolution.",
        "threat_model": "Adversaries may use domain generation algorithms (DGA), fast flux networks, or dynamic DNS (DDNS) services to maintain access to compromised environments and evade static detection techniques.",
        "hypothesis": [
            "Are there frequent DNS queries to domains with high entropy or random subdomains?",
            "Are endpoints resolving multiple IPs for the same domain within a short timeframe?",
            "Is there an unusual frequency of DNS queries indicating a domain generation algorithm (DGA)?"
        ],
        "log_sources": [
            {"type": "DNS Logs", "source": "Microsoft DNS, BIND, Cisco Umbrella, OpenDNS, Zeek (Bro)"},
            {"type": "Network Traffic", "source": "Firewall Logs, NetFlow, Suricata, Zeek (Bro)"},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 22 - DNS Query), EDR solutions"}
        ],
        "detection_methods": [
            "Monitor DNS queries for high-entropy domains or rapidly changing IP resolutions.",
            "Detect frequent queries to DDNS providers or known DGA patterns.",
            "Identify multiple IP resolutions within a short timeframe for a single domain.",
            "Correlate DNS requests with threat intelligence feeds for known malicious domains."
        ],
        "spl_query": "index=dns sourcetype=dns_logs | stats count by query, dest_ip | where count > 50 | sort - count",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1568",
        "hunt_steps": [
            "Run Queries in SIEM: Detect high-frequency DNS queries and dynamic resolutions.",
            "Correlate with Threat Intelligence Feeds: Check domain reputation and associated IPs.",
            "Analyze Network Traffic Behavior: Identify anomalous connections following resolution events.",
            "Investigate Process Execution on Endpoints: Check if malicious scripts or malware are triggering DNS resolutions.",
            "Validate & Escalate: If dynamic resolution is malicious, escalate to IR; refine detection rules if a false positive."
        ],
        "expected_outcomes": [
            "Dynamic Resolution Detected: Block malicious domains, investigate compromised hosts, alert SOC.",
            "No Malicious Activity Found: Improve monitoring of domain resolution behaviors and refine baselines."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1568 (Dynamic Resolution)", "example": "Malware using fast flux or DGA to resolve C2 domains."}
        ],
        "watchlist": [
            "Monitor dynamic DNS (DDNS) providers frequently used by attackers.",
            "Flag high-entropy domain names indicative of domain generation algorithms.",
            "Detect multiple IP resolutions for a single domain within short timeframes."
        ],
        "enhancements": [
            "Implement DNS filtering and sinkholing for known malicious domains.",
            "Enhance detection capabilities with machine learning-based anomaly detection.",
            "Deploy strict egress controls to limit external name resolution."
        ],
        "summary": "Document instances of dynamic resolution used for malicious purposes.",
        "remediation": "Block identified domains, implement stricter DNS monitoring, enforce security controls.",
        "improvements": "Strengthen SIEM analytics to better detect DNS anomalies and dynamic resolution abuses."
    }
