def get_content():
    return {
        "id": "T1669",
        "url_id": "T1669",
        "title": "Wi-Fi Networks",
        "description": "Adversaries may gain initial access to target systems by exploiting nearby Wi-Fi networks, including both open and secured networks, to bridge into victim environments.",
        "tags": ["initial access", "wifi", "wireless", "networking", "APT28", "physical proximity"],
        "tactic": "initial-access",
        "protocol": "Wi-Fi",
        "os": "Linux, Windows, macOS, Network Devices",
        "tips": [
            "Ensure dual-homed systems are properly segmented to prevent pivoting from Wi-Fi into wired networks.",
            "Regularly audit Wi-Fi access logs and monitor for rogue devices or MAC address anomalies.",
            "Disable unused wireless interfaces on infrastructure systems."
        ],
        "data_sources": "Firewall, Network Traffic",
        "log_sources": [
            {"type": "Firewall", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Network Connections", "location": "Wi-Fi access logs", "identify": "Unauthorized or unexpected wireless connections"}
        ],
        "destination_artifacts": [
            {"type": "Firewall Rules", "location": "Access Point Configurations", "identify": "Modified ACLs or allowlists to permit new clients"}
        ],
        "detection_methods": [
            "Monitor MAC address allocations and DHCP lease activity for unusual clients.",
            "Track firewall configuration changes involving Wi-Fi related zones.",
            "Detect abnormal network traffic patterns or volumes from known access points."
        ],
        "apt": ["APT28"],
        "spl_query": [
            "sourcetype=firewall_config_changes rule_name=*WiFi* OR zone=\"wireless\"\n| stats count by rule_name, user, action, _time",
            "index=network_logs sourcetype=dhcp OR sourcetype=zeek:dhcp\n| stats values(mac) as macs, dc(mac) as distinct_count by src_ip, host, _time\n| where distinct_count > 5",
            "sourcetype=zeek:conn OR sourcetype=suricata_flow(interface=\"wlan0\")\n| stats count by src_mac, dest_ip, bytes_in, _time\n| where bytes_in > 500000"
        ],
        "hunt_steps": [
            "Audit Wi-Fi logs for new device associations during off-hours.",
            "Validate all MAC addresses and device types that accessed critical VLANs.",
            "Correlate Wi-Fi activity with endpoint authentication and access attempts."
        ],
        "expected_outcomes": [
            "Detection of unauthorized access via wireless interfaces or unexpected devices bridging into internal infrastructure."
        ],
        "false_positive": "New employee devices or networked IoT devices may initially trigger similar traffic. Validate against known asset inventories.",
        "clearing_steps": [
            "Block rogue MAC addresses at the wireless controller.",
            "Reset Wi-Fi credentials and reissue to validated endpoints.",
            "Review and restore firewall and DHCP configurations."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-network-intrusion"
        ],
        "mitre_mapping": [
            {"tactic": "initial-access", "technique": "T1669", "example": "Wi-Fi Networks"},
            {"tactic": "discovery", "technique": "T1040", "example": "Network Sniffing"}
        ],
        "watchlist": [
            "Access Point authentication attempts from new MACs",
            "Dual-homed devices acting as relays or bridges across Wi-Fi and LAN"
        ],
        "enhancements": [
            "Enable wireless intrusion prevention systems (WIPS) to detect unauthorized APs or clients.",
            "Configure firewalls to restrict lateral movement from wireless segments."
        ],
        "summary": "Wi-Fi Networks can be exploited by threat actors to gain proximity-based or bridged initial access, especially through misconfigured or unsecured access points.",
        "remediation": "Enforce strong encryption and mutual authentication on Wi-Fi networks. Routinely audit connected clients and segment Wi-Fi from critical resources.",
        "improvements": "Deploy centralized management for Wi-Fi APs to monitor and control access across the enterprise.",
        "mitre_version": "17.0"
    }
