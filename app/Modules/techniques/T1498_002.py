def get_content():
    return {
        "id": "T1498.002",
        "url_id": "T1498/002",
        "title": "Network Denial of Service: Reflection Amplification",
        "description": "Adversaries may attempt to cause a denial of service (DoS) by reflecting a high-volume of network traffic to a target. This type of Network DoS takes advantage of a third-party server intermediary that hosts and will respond to a given spoofed source IP address.",
        "tags": ["impact", "reflection", "amplification", "spoofing", "ddos", "availability", "dns", "ntp", "memcached"],
        "tactic": "Impact",
        "protocol": "DNS, NTP, Memcached",
        "os": "Windows, Linux, macOS, IaaS",
        "tips": [
            "Monitor for high response-to-request ratio patterns from external sources.",
            "Deploy ingress and egress filtering (e.g., BCP38) to reduce IP spoofing.",
            "Block inbound traffic from known vulnerable UDP services used in amplification (e.g., open NTP, DNS, Memcached servers).",
            "Work with upstream providers for mitigation and use DDoS protection services."
        ],
        "data_sources": "Network Traffic, Sensor Health",
        "log_sources": [
            {"type": "Network Traffic", "source": "Network Traffic Flow", "destination": ""},
            {"type": "Sensor Health", "source": "Host Status", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Network Traffic", "location": "NetFlow/SFlow", "identify": "Outbound requests to UDP-based amplifiers (DNS, NTP, Memcached)"},
            {"type": "Network Connections", "location": "Firewall logs", "identify": "Unexpected high volume of small UDP packets to known reflection services"},
            {"type": "Volume", "location": "Interface stats", "identify": "Discrepancy between sent request size and received reflected response"}
        ],
        "destination_artifacts": [
            {"type": "Network Traffic", "location": "Victim server interface", "identify": "High-rate inbound traffic with spoofed source IP"},
            {"type": "Sensor Health", "location": "Performance dashboards", "identify": "Availability degradation or latency spikes during attack"},
            {"type": "Volume", "location": "Firewall/load balancer", "identify": "Large packet sizes indicating amplification"}
        ],
        "detection_methods": [
            "Traffic analysis showing asymmetric request/response size ratios.",
            "DNS/NTP/memcached request logs showing spoofed victim IP addresses.",
            "Detection of sudden UDP traffic spikes from public-facing services.",
            "Sensor health metrics showing availability loss or high CPU usage from packet inspection."
        ],
        "apt": ["Notable use by botnets and state-aligned adversaries leveraging DNS/NTP/Memcached DDoS"],
        "spl_query": [
            'index=netflow sourcetype=network_traffic\n| search protocol=udp\n| stats avg(bytes_in), avg(bytes_out) by src_ip\n| where avg(bytes_out) > avg(bytes_in) * 50',
            'index=firewall_logs\n| search "udp" AND (dest_port=53 OR dest_port=123 OR dest_port=11211)\n| stats count by src_ip, dest_port\n| where count > 1000',
            'index=sensor_logs\n| search "CPU usage" OR "interface saturated"\n| stats max(cpu_percent) AS max_cpu, max(bandwidth_usage) AS max_bw'
        ],
        "hunt_steps": [
            "Identify potential reflector servers communicating with internal assets using vulnerable protocols (DNS, NTP, Memcached).",
            "Inspect for spoofed source IPs targeting internal services.",
            "Use pcap and NetFlow to confirm high amplification factor flows.",
            "Check logs for sudden spikes in inbound UDP traffic from diverse IPs."
        ],
        "expected_outcomes": [
            "Detection of reflection-based DDoS behavior via spoofed packets.",
            "Identification of third-party reflectors used in the attack.",
            "Triggering of DDoS defense mechanisms and source attribution."
        ],
        "false_positive": "Legitimate high-traffic UDP services (e.g., public DNS resolvers) may show similar traffic patterns. Verify against request-response sizes and known spoofing behavior.",
        "clearing_steps": [
            "Work with ISPs to block spoofed traffic at upstream routers.",
            "Rate-limit or drop traffic from vulnerable UDP amplification protocols at perimeter.",
            "Engage mitigation services to absorb or reroute large reflected traffic.",
            "Reconfigure exposed services (DNS/NTP/Memcached) to prevent open reflection."
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-resource-abuse"],
        "mitre_mapping": [
            {"tactic": "Impact", "technique": "T1498", "example": "Parent category: DoS via network-level attacks"},
            {"tactic": "Command and Control", "technique": "T1090.002", "example": "Spoofed requests sent via proxy/reflection"},
            {"tactic": "Impact", "technique": "T1498.001", "example": "Combined with direct floods from botnets"}
        ],
        "watchlist": [
            "Outbound UDP traffic to known public reflectors",
            "Inbound UDP floods with no prior communication handshake",
            "Asymmetric NetFlow stats showing large inbound vs. tiny outbound",
            "High response amplification ratios (e.g., 1:1000 or more)"
        ],
        "enhancements": [
            "Integrate DNS/NTP/Memcached abuse signatures into IDS/IPS.",
            "Block open recursive resolvers and restrict UDP response sizes.",
            "Deploy anti-spoofing protections at the edge (BCP38)."
        ],
        "summary": "Reflection Amplification attacks use vulnerable UDP services to bounce traffic off third-party systems back to a target using spoofed source IPs. This technique greatly amplifies attack traffic and is difficult to mitigate without coordination across network infrastructure.",
        "remediation": "Block vulnerable amplification services at perimeter. Work with upstream providers and ISPs to mitigate and trace spoofed packet origins. Harden internal services and monitor UDP flows closely.",
        "improvements": "Deploy anti-spoofing and ingress filtering, simulate amplification red team exercises, and automate reflector fingerprinting using known abuse databases.",
        "mitre_version": "16.1"
    }
