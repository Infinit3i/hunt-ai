def get_content():
    return {
        "id": "T1499.001",
        "url_id": "T1499/001",
        "title": "Endpoint Denial of Service: OS Exhaustion Flood",
        "description": "Adversaries may launch a denial of service (DoS) attack targeting an endpoint’s operating system (OS) by exhausting its capacity or internal resource limits, such as via SYN or ACK floods.",
        "tags": ["dos", "tcp flood", "syn flood", "ack flood", "impact", "resource exhaustion", "system limits"],
        "tactic": "Impact",
        "protocol": "TCP",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor for abnormal volumes of incomplete TCP handshakes (SYNs without ACKs).",
            "Use SYN cookies or firewall rules to detect and block excessive TCP floods.",
            "Track CPU and kernel queue utilization for signs of packet processing exhaustion."
        ],
        "data_sources": "Network Traffic: Network Traffic Content, Network Traffic: Network Traffic Flow, Sensor Health: Host Status",
        "log_sources": [
            {"type": "Network Traffic", "source": "Firewall", "destination": "Sensor"},
            {"type": "Sensor Health", "source": "Host OS", "destination": "Monitoring System"}
        ],
        "source_artifacts": [
            {"type": "SYN/ACK Packet Flood", "location": "Inbound Network", "identify": "High-rate of partial handshakes or invalid ACKs"}
        ],
        "destination_artifacts": [
            {"type": "TCP Queue Saturation", "location": "Kernel State Table", "identify": "TCP connections stuck in SYN_RECV or invalid ACK lookup"}
        ],
        "detection_methods": [
            "Analyze TCP state counts in system metrics (e.g., `netstat` or `ss`)",
            "Detect packet floods via NetFlow or pcap inspection",
            "Alert on excessive SYNs without follow-up ACKs"
        ],
        "apt": [],
        "spl_query": [
            "index=network_traffic sourcetype=firewall_logs action=allow protocol=tcp\n| stats count by src_ip, tcp_flags\n| where tcp_flags=\"SYN\" AND count > 500"
        ],
        "hunt_steps": [
            "Search for spikes in half-open TCP connections on the host.",
            "Analyze packet captures for repeated SYNs or mismatched ACKs.",
            "Cross-reference with firewall or IDS logs showing connection floods."
        ],
        "expected_outcomes": [
            "Identification of TCP exhaustion attempts at the OS layer",
            "Early indicators of denial of service via protocol abuse"
        ],
        "false_positive": "Traffic from aggressive vulnerability scanners or broken clients may resemble low-level SYN floods.",
        "clearing_steps": [
            "Enable SYN cookies or TCP backlog tuning on the affected host.",
            "Block malicious IPs using perimeter firewalls or host firewall rules.",
            "Rate-limit new TCP connections per IP address."
        ],
        "mitre_mapping": [
            {"tactic": "Impact", "technique": "T1498", "example": "Network Denial of Service"},
            {"tactic": "Impact", "technique": "T1499", "example": "Endpoint Denial of Service"}
        ],
        "watchlist": [
            "Increase in SYN_RECV state connections",
            "Drop in host responsiveness or availability after TCP flood indicators"
        ],
        "enhancements": [
            "Deploy network-layer DDoS mitigation tools with connection tracking.",
            "Use OS-level rate limiting (e.g., iptables, PF, or Windows Firewall advanced rules)."
        ],
        "summary": "OS Exhaustion Floods focus on overwhelming the TCP/IP stack or internal OS resource limits by abusing stateful protocol behavior like SYN/ACK processing, leading to service disruption.",
        "remediation": "Use SYN cookies, increase TCP backlog queue, deploy perimeter protection, and patch for kernel-level DoS weaknesses.",
        "improvements": "Enhance observability of network stack behavior and deploy anomaly-based TCP session profiling for critical systems."
    }
