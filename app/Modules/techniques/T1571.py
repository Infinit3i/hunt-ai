def get_content():
    return {
        "id": "T1571",
        "url_id": "T1571",
        "title": "Non-Standard Port",
        "description": "Adversaries may communicate using a protocol and port pairing that is atypical or deliberately altered to bypass detection and evade network security controls. For instance, they may use HTTPS over ports like 8088 or 587 rather than the standard port 443. This technique can disrupt protocol-based detection, obfuscate malicious traffic, and hinder analysis by altering expectations around port behavior.\n\nNon-standard ports can also be configured directly on the victim system, such as altering Registry keys or other configuration settings to redirect legitimate protocols to attacker-controlled services or binaries.",
        "tags": ["c2", "port_hiding", "network_evasion", "uncommon_port"],
        "tactic": "Command and Control",
        "protocol": "TCP, UDP, Custom Protocols",
        "os": "Platform Agnostic",
        "tips": [
            "Cross-reference protocol usage with expected port assignments.",
            "Create alerts for sudden spikes in traffic over uncommon ports.",
            "Monitor baseline port behavior across endpoints and servers."
        ],
        "data_sources": "Network Traffic, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS)",
        "log_sources": [
            {"type": "Network Traffic", "source": "Zeek (Bro), Suricata, Wireshark", "destination": ""},
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA", "destination": ""},
            {"type": "Proxy Logs", "source": "Zscaler, Bluecoat, McAfee Web Gateway", "destination": ""},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 3, 22), EDR (CrowdStrike, Defender ATP)", "destination": ""},
            {"type": "IDS", "source": "Snort, Suricata, Zeek (Bro)", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Anomalous Port Traffic", "location": "Perimeter Devices", "identify": "Unexpected outbound connections on non-default ports"}
        ],
        "destination_artifacts": [
            {"type": "C2 Listener", "location": "Remote IP on Uncommon Port", "identify": "Server listening on a port unrelated to advertised service"}
        ],
        "detection_methods": [
            "Monitor for outbound network traffic on uncommon ports.",
            "Detect protocol mismatches where application traffic does not match expected port behavior.",
            "Identify C2 traffic using dynamically assigned or custom ports."
        ],
        "apt": [
            "APT29", "FIN7", "OceanLotus", "TRITON", "WIRTE", "Elfin", "PingPull", "UNC3890", "HOPLIGHT", "Cobalt Group"
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search port!=80 AND port!=443 AND port!=22 AND port!=53 \n| stats count by src_ip, dest_ip, port"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify traffic on non-standard ports.",
            "Analyze Protocol Mismatches: Detect anomalies between expected and observed network behavior.",
            "Monitor for Dynamic Port Usage: Identify patterns in C2 traffic across varying ports.",
            "Correlate with Threat Intelligence: Compare with known C2 techniques utilizing non-standard ports.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Non-Standard Port C2 Detected: Block malicious traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for non-standard port usage in C2."
        ],
        "false_positive": "Some legitimate applications may use non-default ports, especially for testing, cloud-native services, or VPNs. Validate against asset and service inventories.",
        "clearing_steps": [
            "Block identified non-standard port usage tied to malicious behavior.",
            "Audit systems for unauthorized port reconfiguration.",
            "Reset services modified to communicate over non-standard ports.",
            "Apply updated firewall rules and deep packet inspection for evasive protocol behaviors."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1571 (Non-Standard Port)", "example": "C2 traffic using TCP port 8443 instead of 443."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data exfiltrated through UDP port 2222."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs containing non-standard port usage."}
        ],
        "watchlist": [
            "Flag outbound connections using uncommon ports.",
            "Monitor for anomalies in port usage trends.",
            "Detect unauthorized applications using non-standard ports for communication."
        ],
        "enhancements": [
            "Deploy network segmentation to restrict non-standard port usage.",
            "Implement deep packet inspection to analyze traffic on uncommon ports.",
            "Improve correlation between non-standard ports and known threat actor techniques."
        ],
        "summary": "Detect and mitigate adversaries leveraging non-standard ports for C2 channels, often to bypass traditional detection mechanisms or confuse traffic analysts.",
        "remediation": "Block unauthorized non-standard port communications, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of non-standard port-based command-and-control techniques.",
        "mitre_version": "16.1"
    }
