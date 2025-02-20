def get_content():
    return {
        "id": "T1011",
        "url_id": "1011",
        "title": "Exfiltration Over Other Network Medium",
        "tactic": "Exfiltration",
        "data_sources": "Network Traffic, System Logs",
        "protocol": "Varies (Bluetooth, Cellular, Radio, etc.)",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries exfiltrate data using alternate network mediums to evade detection.",
        "scope": "Monitor non-traditional network traffic for anomalies.",
        "threat_model": "Adversaries may use covert channels, such as radio frequencies, cellular data, or infrared, to exfiltrate data outside the primary monitored network.",
        "hypothesis": [
            "Are there unauthorized Bluetooth or cellular connections on critical systems?",
            "Is there unexpected outbound network traffic to unfamiliar destinations?"
        ],
        "tips": [
            "Monitor for unusual peripheral device connections.",
            "Analyze network traffic for unexpected data transmissions.",
            "Review logs for unauthorized wireless communications."
        ],
        "log_sources": [
            {"type": "Network", "source": "Firewall Logs", "destination": "SIEM"},
            {"type": "System", "source": "Windows Event Logs", "destination": "Endpoint Security Platform"}
        ],
        "source_artifacts": [
            {"type": "Registry", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\BthPort", "identify": "Bluetooth activity"},
            {"type": "System Log", "location": "/var/log/syslog", "identify": "Unusual network device activity"}
        ],
        "destination_artifacts": [
            {"type": "Network Traffic", "location": "Packet Captures", "identify": "Unusual outbound connections"}
        ],
        "detection_methods": [
            "Analyze network traffic for non-standard exfiltration methods.",
            "Monitor for unauthorized wireless communications.",
            "Inspect system logs for new network adapters."
        ],
        "spl_query": [
            "index=network_logs sourcetype=firewall_logs dest_port!=80 dest_port!=443 | stats count by dest_ip"
        ],
        "hunt_steps": [
            "Identify endpoints with unexpected wireless interfaces.",
            "Review outbound network traffic for suspicious patterns.",
            "Analyze firewall logs for anomalous connections."
        ],
        "expected_outcomes": [
            "Detection of unauthorized exfiltration methods.",
            "Identification of compromised endpoints using alternative network mediums."
        ],
        "false_positive": "Some legitimate applications may use alternative network paths, such as Bluetooth file transfers or cellular failover.",
        "clearing_steps": [
            "Disable unauthorized wireless interfaces.",
            "Reconfigure firewall rules to block unexpected traffic.",
            "Investigate and remove malicious processes facilitating exfiltration."
        ],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1011", "example": "Data exfiltrated over Bluetooth"}
        ],
        "watchlist": [
            "New or unauthorized network interfaces appearing on endpoints.",
            "Unusual outbound connections bypassing traditional network monitoring."
        ],
        "enhancements": [
            "Deploy endpoint protection to detect unauthorized wireless activity.",
            "Enhance network segmentation to limit data exfiltration routes."
        ],
        "summary": "Adversaries may use alternative network mediums like Bluetooth, radio, or cellular networks to exfiltrate data, bypassing traditional network monitoring.",
        "remediation": "Enforce strict policies on wireless communications and monitor network activity for anomalies.",
        "improvements": "Implement more granular logging for wireless interfaces and conduct periodic audits of network devices."
    }