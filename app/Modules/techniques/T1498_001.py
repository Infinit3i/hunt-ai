def get_content():
    return {
        "id": "T1498.001",
        "url_id": "T1498/001",
        "title": "Network Denial of Service: Direct Network Flood",
        "description": "Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target. This DoS attack may also reduce the availability and functionality of the targeted system(s) and network.",
        "tags": ["impact", "network flooding", "ddos", "botnet", "availability", "udp flood", "icmp flood", "tcp flood"],
        "tactic": "Impact",
        "protocol": "UDP, ICMP, TCP",
        "os": "Windows, Linux, macOS, IaaS",
        "tips": [
            "Use anomaly-based detection on NetFlow or packet capture tools to catch traffic spikes early.",
            "Establish baseline bandwidth utilization to better detect abnormalities.",
            "Work with ISPs and upstream providers to implement blackholing or scrubbing during volumetric events.",
            "Use geofencing or threat intelligence lists to block botnet-heavy regions during active flooding."
        ],
        "data_sources": "Network Traffic, Sensor Health",
        "log_sources": [
            {"type": "Network Traffic", "source": "Network Traffic Flow", "destination": ""},
            {"type": "Sensor Health", "source": "Host Status", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Network Connections", "location": "Firewall/Netflow", "identify": "High-volume packets originating from many IPs targeting one system"},
            {"type": "Sensor Health", "location": "Host Monitoring Tools", "identify": "Interface saturation and packet drop alerts"},
            {"type": "Network Traffic", "location": "Inbound flows", "identify": "Protocol-specific spikes (UDP flood, SYN flood, ICMP ping flood)"}
        ],
        "destination_artifacts": [
            {"type": "Volume", "location": "Router/firewall metrics", "identify": "Throughput exceeding NIC/interface limits"},
            {"type": "Sensor Health", "location": "Web server logs", "identify": "Dropped sessions or service-level outage"},
            {"type": "Network Traffic", "location": "Target server interface", "identify": "High pps (packets per second) with no legitimate payloads"}
        ],
        "detection_methods": [
            "Use flow-based detection to monitor for sudden increases in traffic volume to specific IPs.",
            "Implement volumetric DoS detection on firewalls, IDS/IPS, or cloud security gateways.",
            "Analyze packet captures for known DDoS signatures like constant SYNs or malformed UDP frames.",
            "Track failed session initiations that do not complete TCP handshake (e.g., SYN flood)."
        ],
        "apt": ["Iranian Botnet (as referenced in USNYAG 2016 indictment)"],
        "spl_query": [
            'index=netflow sourcetype=network_traffic\n| stats count by src_ip, dest_ip, protocol\n| where count > 1000',
            'index=sensor_logs\n| search "interface utilization" OR "traffic spike"\n| stats max(bytes_in) AS max_in, max(bytes_out) AS max_out by device',
            'index=firewall_logs action=allowed\n| stats count by src_ip, protocol\n| where count > 500 AND protocol IN ("icmp", "udp", "tcp")'
        ],
        "hunt_steps": [
            "Correlate flow records to detect concentration of traffic to a single endpoint.",
            "Verify anomaly against usage history and scheduled system tasks.",
            "Inspect for IP spoofing or known botnet IPs using threat intelligence.",
            "Review sensor health metrics for hardware strain or bandwidth exhaustion."
        ],
        "expected_outcomes": [
            "Early warning of large-scale DDoS in progress based on flow pattern.",
            "Classification of attack type (SYN flood, UDP flood, etc.) to inform mitigation strategy.",
            "Attribution of attack to botnet or threat actor if indicators match known campaigns."
        ],
        "false_positive": "Burst traffic from legitimate clients (e.g., product launch, software update) can mimic flood. Validate with business context and protocol usage.",
        "clearing_steps": [
            "Contact upstream provider to implement rate limiting or blackhole mitigation.",
            "Update firewall ACLs or thresholds to block or filter repetitive IPs.",
            "Restart impacted services and monitor interface utilization.",
            "Engage DDoS mitigation partners or enable on-demand WAF protections."
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-resource-abuse"],
        "mitre_mapping": [
            {"tactic": "Impact", "technique": "T1498", "example": "Parent category of volumetric DoS using network traffic floods"},
            {"tactic": "Command and Control", "technique": "T1090.002", "example": "Botnets controlling the attack via external infrastructure"}
        ],
        "watchlist": [
            "Large volume of ICMP/UDP/TCP packets from diverse or spoofed sources",
            "Spikes in interface traffic without corresponding web/app logs",
            "Drop in server responsiveness without internal issues",
            "Traffic with low TTL (time to live) values from bots"
        ],
        "enhancements": [
            "Integrate threat intel feeds for DDoS botnet IPs.",
            "Automate ACL responses for burst protocol-specific flooding.",
            "Correlate NetFlow and firewall logs with packet capture analysis."
        ],
        "summary": "Direct Network Floods overwhelm target infrastructure by sending massive traffic volumes using common protocols like UDP, ICMP, or TCP. These attacks are often coordinated via botnets and can bring down services by saturating links or exhausting compute resources.",
        "remediation": "Use upstream filtering, rate-limiting, blackholing, or ISP collaboration to mitigate volumetric attacks. Rotate IPs and scale bandwidth if feasible.",
        "improvements": "Build scalable edge defenses, enable cloud-based mitigation, simulate DDoS testing with red team exercises, and train staff on high-tempo incident response procedures.",
        "mitre_version": "16.1"
    }
