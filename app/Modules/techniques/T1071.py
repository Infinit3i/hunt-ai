def get_content():
    return {
        "id": "T1071",
        "url_id": "T1071",
        "title": "Application Layer Protocol",
        "tactic": "Command and Control",
        "data_sources": "Firewall, Proxy, DNS, PCAP",
        "protocol": "HTTP, HTTPS, DNS, TCP",
        "os": "Platform Agnostic",
        "objective": "Detect and investigate suspicious application layer communications, which may indicate covert channels, command-and-control (C2) traffic, or exfiltration attempts.",
        "scope": "Monitor application layer protocols (HTTP, HTTPS, DNS, TCP) for anomalies. Identify deviations from baseline network behavior, including irregular HTTP headers and DNS queries.",
        "threat_model": "Adversaries may abuse application layer protocols for covert C2 communication, data exfiltration, or persistence.",
        "hypothesis": [
            "Are there unexpected HTTP methods or unusual HTTP headers in network traffic?",
            "Are there suspicious DNS queries that could indicate DNS tunneling?",
            "Is encrypted HTTPS traffic unusually persistent or higher in volume than normal?"
        ],
        "log_sources": [
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA, CheckPoint"},
            {"type": "Proxy Logs", "source": "Zscaler, Bluecoat, McAfee Web Gateway"},
            {"type": "DNS Logs", "source": "Microsoft DNS, OpenDNS, Cisco Umbrella, Zeek (Bro)"},
            {"type": "PCAP Logs", "source": "Suricata, Zeek (Bro), Wireshark"}
        ],
        "detection_methods": [
            "Monitor HTTP/S traffic for unusual request methods or headers.",
            "Detect DNS queries with long subdomains, which may indicate tunneling.",
            "Analyze TCP traffic for suspicious C2-like behavior."
        ],
        "spl_query": ["index=firewall sourcetype=firewall_logs (dest_port=80 OR dest_port=443) | stats count by src_ip, dest_ip, http_method, url | sort - count"],
        "hunt_steps": [
            "Run Queries in SIEM: Detect unusual HTTP request methods and persistent HTTPS sessions.",
            "Identify long DNS queries that may indicate tunneling.",
            "Correlate with Threat Intelligence Feeds: Validate suspicious domain requests against threat intelligence feeds.",
            "Analyze Traffic Behavior: Determine if C2 communication is occurring over application layer protocols.",
            "Investigate Process Execution on Endpoints: Check if PowerShell, Python, or scripts are making outbound HTTP requests.",
            "Validate & Escalate: If suspicious activity is detected → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Malicious Application Layer Traffic Detected: Block C2 traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve network monitoring rules for application-layer traffic."
        ],
        "mitre_mapping": [
            {"tactic": "Command & Control", "technique": "T1095 (Non-Standard Port Usage)", "example": "Attackers may switch to alternate ports to avoid detection."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data may be transmitted using HTTP/S or DNS tunnels."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Attackers may delete logs to erase evidence of HTTP C2 traffic."},
            {"tactic": "Persistence", "technique": "T1098 (Account Manipulation)", "example": "Adversaries may create or modify accounts to maintain access."},
            {"tactic": "Execution", "technique": "T1204.002 (User Execution - Malicious File)", "example": "Malware may execute scripts to maintain C2 communication."}
        ],
        "watchlist": [
            "Flag suspicious HTTP/S, DNS, and TCP traffic patterns.",
            "Detect long-duration HTTPS connections indicative of covert C2.",
            "Monitor anomalous DNS queries for beaconing activity."
        ],
        "enhancements": [
            "Deploy deep packet inspection (DPI) for advanced protocol analysis.",
            "Block known malicious domains and unauthorized proxy usage.",
            "Enable logging and monitoring of encrypted outbound sessions."
        ],
        "summary": "Monitor application layer traffic for anomalies and covert C2 channels.",
        "remediation": "Block unauthorized application layer traffic, enforce network segmentation, and improve protocol monitoring.",
        "improvements": "Enhance anomaly-based detection for encrypted and DNS-based communication." 
    }
