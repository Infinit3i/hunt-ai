def get_content():
    return {
        "id": "T1499.002",
        "url_id": "T1499/002",
        "title": "Endpoint Denial of Service: Service Exhaustion Flood",
        "description": "Adversaries may flood a system’s exposed services such as web servers or DNS with high volumes of requests to exhaust the underlying software or protocol limits, causing service unavailability.",
        "tags": ["dos", "http flood", "ssl renegotiation", "service exhaustion", "impact", "availability"],
        "tactic": "Impact",
        "protocol": "HTTP, HTTPS, DNS, SSL/TLS",
        "os": "IaaS, Linux, Windows, macOS",
        "tips": [
            "Enable rate-limiting and connection throttling for exposed services.",
            "Monitor for repeated SSL renegotiation or handshake attempts.",
            "Correlate error logs (HTTP 500, 503) with traffic spikes."
        ],
        "data_sources": "Application Log: Application Log Content, Network Traffic: Network Traffic Content, Network Traffic: Network Traffic Flow, Sensor Health: Host Status",
        "log_sources": [
            {"type": "Application Log", "source": "Web/DNS Server", "destination": "SIEM"},
            {"type": "Network Traffic", "source": "Firewall", "destination": "Monitoring System"},
            {"type": "Sensor Health", "source": "Service Status", "destination": "Infra Watch"}
        ],
        "source_artifacts": [
            {"type": "Flood Requests", "location": "External Network", "identify": "Rapid HTTP/SSL/DNS requests in burst patterns"}
        ],
        "destination_artifacts": [
            {"type": "Error Logs", "location": "Service Log Files", "identify": "Spike in 5xx status codes or renegotiation failures"}
        ],
        "detection_methods": [
            "Real-time inspection of HTTP/DNS/SSL logs for anomaly volume",
            "Detection of excessive renegotiation handshakes",
            "Monitoring traffic rate per source and per endpoint"
        ],
        "apt": [],
        "spl_query": [
            "index=weblogs status_code>=500\n| stats count by client_ip, uri_path",
            "index=ssl_logs event_type=renegotiation\n| stats count by src_ip, dest_ip"
        ],
        "hunt_steps": [
            "Identify IPs with frequent 500/503 error triggers.",
            "Check for renegotiation flood patterns in SSL logs.",
            "Correlate service load spikes with client IP behavior."
        ],
        "expected_outcomes": [
            "Detection of raw-volume service abuse leading to unavailability.",
            "Insight into exhaustion at protocol or software handling layers."
        ],
        "false_positive": "High-traffic campaigns or legitimate bulk service access (e.g., updates, testing) may resemble floods.",
        "clearing_steps": [
            "Implement reverse proxies, WAFs, or DNS caching layers.",
            "Apply rate limits or block abusive IPs temporarily.",
            "Reboot/restart services under attack while isolating the source."
        ],
        "mitre_mapping": [
            {"tactic": "Impact", "technique": "T1498", "example": "Application Layer Protocol Flood"},
            {"tactic": "Impact", "technique": "T1499", "example": "Endpoint Denial of Service"}
        ],
        "watchlist": [
            "Burst connections from same IP to service ports (80, 443, 53)",
            "Repeated SSL renegotiations from non-browser clients"
        ],
        "enhancements": [
            "Enable SSL session reuse and disable renegotiation where possible.",
            "Use load balancers with flood detection logic."
        ],
        "summary": "Service Exhaustion Floods aim to overwhelm application-level services like HTTP or DNS by leveraging high volume requests or protocol-level abuse like SSL renegotiation, rendering services inaccessible.",
        "remediation": "Harden services with caching, rate limiting, protocol restrictions, and failover strategies.",
        "improvements": "Integrate service-specific anomaly models into your SIEM or SOAR playbooks for automated detection and response."
    }
