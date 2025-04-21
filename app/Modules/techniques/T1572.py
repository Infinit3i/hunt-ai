def get_content():
    return {
        "id": "T1572",
        "url_id": "T1572",
        "title": "Protocol Tunneling",
        "description": "Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection or filtering and to reach otherwise inaccessible systems. This technique allows adversaries to encapsulate C2 traffic within protocols such as ICMP, DNS, HTTPS, or SSH to bypass security mechanisms.\n\nTunneling may conceal malicious traffic by blending into normal communications or providing an additional encryption layer. Protocol tunneling is often used alongside techniques like Dynamic Resolution (e.g., DNS-over-HTTPS) or Proxying to evade detection and maintain stealthy, persistent communication channels.",
        "tags": ["protocol_tunneling", "covert_c2", "dns_tunnel", "icmp_tunnel", "stealth"],
        "tactic": "Command and Control",
        "protocol": "ICMP, HTTP, HTTPS, DNS, SSH, Custom Tunneling Protocols",
        "os": "Platform Agnostic",
        "tips": [
            "Watch for long-duration, low-bandwidth sessions over protocols like ICMP or DNS.",
            "Implement rate limiting and deep inspection on DNS and ICMP channels.",
            "Correlate firewall/proxy logs with endpoint activity for unexpected tunnels."
        ],
        "data_sources": "Network Traffic, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS), VPN Logs",
        "log_sources": [
            {"type": "Network Traffic", "source": "Zeek (Bro), Suricata, Wireshark", "destination": ""},
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA", "destination": ""},
            {"type": "Proxy Logs", "source": "Zscaler, Bluecoat, McAfee Web Gateway", "destination": ""},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 3, 22), EDR (CrowdStrike, Defender ATP)", "destination": ""},
            {"type": "IDS", "source": "Snort, Suricata, Zeek (Bro)", "destination": ""},
            {"type": "VPN Logs", "source": "Corporate VPN Solutions, OpenVPN, WireGuard", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Tunnel Packets", "location": "Network Perimeter Logs", "identify": "Suspicious ICMP/DNS encapsulation traffic patterns"}
        ],
        "destination_artifacts": [
            {"type": "Command Channel", "location": "Remote C2 infrastructure", "identify": "Endpoints receiving tunneled control commands"}
        ],
        "detection_methods": [
            "Monitor for excessive or anomalous DNS, ICMP, or HTTP traffic.",
            "Detect protocol encapsulation mismatches in network traffic.",
            "Identify long-duration, low-bandwidth connections indicative of persistent tunnels."
        ],
        "apt": [
            "APT34", "Cobalt Group", "Sandworm", "FIN6", "Lunar (Turla)", "Elephant Beetle", "Black Basta", "PIONEER KITTEN", "APT40", "Lyceum"
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search protocol=*icmp* OR protocol=*dns* OR protocol=*http* \n| stats count by src_ip, dest_ip, protocol"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify potential protocol tunneling activity.",
            "Analyze Packet Payloads: Detect anomalies in encapsulated traffic.",
            "Monitor for Unusual Data Transfer: Identify large volumes of data hidden within legitimate protocols.",
            "Correlate with Threat Intelligence: Compare with known tunneling techniques used by adversaries.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Protocol Tunneling Detected: Block malicious tunneling traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for protocol tunneling techniques."
        ],
        "false_positive": "Some legacy systems or VPN tools may exhibit similar traffic. Validate with software inventory and behavior baselines.",
        "clearing_steps": [
            "Terminate abnormal network sessions involving protocol tunneling.",
            "Remove unauthorized tunneling tools or scripts from endpoints.",
            "Apply network filtering and update IDS signatures for tunneling patterns.",
            "Reset affected credentials and revoke compromised access tokens."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1572 (Protocol Tunneling)", "example": "C2 traffic encapsulated within ICMP packets."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data exfiltrated using DNS tunneling."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs after using protocol tunneling."}
        ],
        "watchlist": [
            "Flag high-frequency DNS requests to uncommon domains.",
            "Monitor for unexpected encapsulation of data in ICMP packets.",
            "Detect unauthorized VPN or tunneling activity in corporate environments."
        ],
        "enhancements": [
            "Deploy deep packet inspection to analyze encapsulated traffic.",
            "Implement behavioral analytics to detect protocol tunneling misuse.",
            "Improve correlation between tunneling activity and known threat actor techniques."
        ],
        "summary": "Detect and mitigate covert command-and-control channels established through protocol tunneling techniques. These methods allow adversaries to encapsulate malicious communications within legitimate-looking traffic such as DNS, HTTPS, and ICMP.",
        "remediation": "Block unauthorized tunneling traffic, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of protocol tunneling-based command-and-control techniques.",
        "mitre_version": "16.1"
    }
