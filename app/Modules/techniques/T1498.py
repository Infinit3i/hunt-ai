def get_content():
    return {
        "id": "T1498",
        "url_id": "T1498",
        "title": "Network Denial of Service",
        "description": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Network DoS can be performed by exhausting the network bandwidth services rely on.",
        "tags": ["impact", "ddos", "network flooding", "availability", "botnet", "reflection attack", "spoofing"],
        "tactic": "Impact",
        "protocol": "TCP, UDP, ICMP",
        "os": "Windows, Linux, macOS, Containers, IaaS",
        "tips": [
            "Set up rate limiting and anomaly-based traffic detection on edge routers.",
            "Deploy upstream scrubbing services or CDNs to absorb volumetric attacks.",
            "Inspect flow data for IP spoofing or reflection patterns.",
            "Establish bandwidth baselines for known applications and monitor for spikes."
        ],
        "data_sources": "Network Traffic, Sensor Health",
        "log_sources": [
            {"type": "Network Traffic", "source": "Network Traffic Flow", "destination": ""},
            {"type": "Sensor Health", "source": "Host Status", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Network Connections", "location": "Firewall and NetFlow logs", "identify": "Unusual spikes in traffic from a wide range of IPs"},
            {"type": "Sensor Health", "location": "Monitoring Tools", "identify": "CPU or memory exhaustion on network appliances"},
            {"type": "Volume", "location": "Link saturation detection", "identify": "Bandwidth utilization exceeding normal operational capacity"}
        ],
        "destination_artifacts": [
            {"type": "Network Traffic", "location": "Targeted services", "identify": "Flooded with protocol-specific packets (e.g., SYN, UDP floods)"},
            {"type": "Sensor Health", "location": "Web/application host", "identify": "Downtime or performance degradation on public services"}
        ],
        "detection_methods": [
            "NetFlow or sFlow-based anomaly detection.",
            "SNMP counters for traffic and interface errors.",
            "Traffic inspection for DDoS signatures (e.g., same-payload rapid requests).",
            "Rate anomaly detection using SIEM correlation rules."
        ],
        "apt": ["Lazarus", "GRU"],
        "spl_query": [
            'index=network_traffic sourcetype=netflow\n| timechart span=1m avg(bytes_in) AS avg_in, avg(bytes_out) AS avg_out\n| eval total_bw=avg_in+avg_out\n| where total_bw > 1000000000',
            'index=network_traffic\n| search protocol=ICMP OR protocol=UDP\n| stats count by src_ip, dest_ip, dest_port\n| where count > 1000',
            'index=sensor_logs\n| search "resource utilization" OR "interface saturation"\n| stats count by device, metric'
        ],
        "hunt_steps": [
            "Use flow analytics to identify distributed sources of traffic hitting a single service.",
            "Analyze time-based traffic patterns to detect sudden surges.",
            "Verify if impacted services are reachable internally vs. externally.",
            "Correlate ISP logs with internal monitoring to confirm DDoS origin and type."
        ],
        "expected_outcomes": [
            "Detection of active or impending DDoS attacks targeting infrastructure.",
            "Attribution of source IPs or botnets used in volumetric attacks.",
            "Triggering of mitigation protocols such as scrubbing or IP filtering."
        ],
        "false_positive": "Legitimate traffic surges from marketing campaigns or software updates may mimic DDoS patterns. Confirm with business units and review packet structure.",
        "clearing_steps": [
            "Engage upstream ISP or CDN provider for scrubbing assistance.",
            "Apply geo-blocking or IP-based rate limits temporarily.",
            "Isolate target services and switch traffic routing to alternate paths.",
            "Clear firewall states and enable DoS protection features post-mitigation."
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-resource-abuse"],
        "mitre_mapping": [
            {"tactic": "Impact", "technique": "T1499", "example": "Endpoint DoS to complement network-layer attack"},
            {"tactic": "Command and Control", "technique": "T1090.002", "example": "Proxy infrastructure used to hide botnet origin"}
        ],
        "watchlist": [
            "Burst traffic from random IPs with common destination",
            "Single protocol floods (SYN/UDP/ICMP) with no expected response",
            "DNS amplification behavior or signs of reflection",
            "Outbound alert logs of traffic exhaustion from services"
        ],
        "enhancements": [
            "Automate threshold-based blackhole routing and geo-IP blocking.",
            "Integrate honeypots to attract and fingerprint DDoS botnets.",
            "Log packet payload sizes for volumetric attacks and analyze entropy."
        ],
        "summary": "Network Denial of Service aims to overwhelm services or infrastructure by exhausting bandwidth using massive volumes of malicious traffic. These attacks often use botnets, spoofing, or amplification to degrade service availability.",
        "remediation": "Engage upstream filtering services, apply emergency ACLs, and reroute network traffic. Use ISP coordination and forensic flow data for attribution and longer-term defense.",
        "improvements": "Enhance volumetric detection at edge routers, simulate DDoS red-teaming for response testing, and implement rate-limiting at application and firewall levels.",
        "mitre_version": "16.1"
    }
