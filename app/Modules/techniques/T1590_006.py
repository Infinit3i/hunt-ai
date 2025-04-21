def get_content():
    return {
        "id": "T1590.006",
        "url_id": "T1590/006",
        "title": "Gather Victim Network Information: Network Security Appliances",
        "description": "Adversaries may gather information about the victim's network security appliances that can be used during targeting. This includes data on firewalls, IDS/IPS, proxies, content filters, and other network defense infrastructure, often to aid in evasion or targeting weaknesses.",
        "tags": ["reconnaissance", "network-security", "defensive-evasion", "firewall-bypass", "osint"],
        "tactic": "Reconnaissance",
        "protocol": "TCP/IP",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Use active monitoring to detect and correlate scans targeting firewall or proxy ports.",
            "Identify indirect reconnaissance activity from public scan engines or bots.",
            "Monitor threat intelligence feeds for NIDS evasion tactics used in-the-wild."
        ],
        "data_sources": "Network Traffic, Command, Internet Scan, Application Log, Firewall, Sensor Health, Domain Name, Persona",
        "log_sources": [
            {"type": "Firewall", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Internet Scan", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Network Connections", "location": "pcap or flow logs", "identify": "Scanning behavior targeting known appliance ports"},
            {"type": "Command History", "location": "~/.bash_history", "identify": "Use of tools like nmap, masscan, or banner grabbers"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Detect repeated probes to ports associated with security appliances (e.g., 22, 161, 443, 1812, 8080)",
            "Correlate active scanning logs with known attacker fingerprints",
            "Monitor for TLS handshake anomalies revealing proxy inspection or filtering"
        ],
        "apt": ["APT41", "Volt Typhoon", "Sandworm Team"],
        "spl_query": [
            'index=network_logs dest_port IN (22, 443, 8080, 161, 1812) action="deny"\n| stats count by src_ip, dest_port',
            'index=firewall_logs signature="Access to firewall/proxy interface"\n| stats count by src_ip, uri',
            'index=ids_logs alert="scan" AND protocol="TCP"\n| stats count by src_ip, signature'
        ],
        "hunt_steps": [
            "Review firewall logs for interface probing or login attempts",
            "Analyze scan telemetry for frequency targeting typical appliance IP blocks",
            "Correlate traffic to online tools like Shodan or ZoomEye"
        ],
        "expected_outcomes": [
            "Identification of adversary reconnaissance targeting network defense layers",
            "Detection of attempts to enumerate and fingerprint NIDS or firewall appliances",
            "Alerts on scanning traffic that aligns with evasion or mapping TTPs"
        ],
        "false_positive": "Vulnerability scanners or security audits may perform similar port scans. Confirm with asset owners and scheduled assessments.",
        "clearing_steps": [
            "Purge nmap/masscan history and remove scan tools:\nCommand: `rm -rf ~/.nmap ~/.masscan ~/.bash_history`",
            "Review DNS and flow telemetry for past banner-grabbing attempts"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Reconnaissance", "technique": "T1595", "example": "Active Scanning"},
            {"tactic": "Resource Development", "technique": "T1588", "example": "Obtain Capabilities"},
            {"tactic": "Initial Access", "technique": "T1133", "example": "External Remote Services"}
        ],
        "watchlist": [
            "Probes to firewall/web console ports (e.g., 8443, 4444, 9443)",
            "Traffic to common appliance login paths like `/admin`, `/cgi-bin`, `/mgmt`",
            "Suspicious scanning behavior in off-hours from non-IT ranges"
        ],
        "enhancements": [
            "Deploy canary firewall interfaces that trigger alerts on any access",
            "Apply behavior-based heuristics to distinguish scanning vs normal admin traffic"
        ],
        "summary": "This technique focuses on the identification of security infrastructure deployed within a victim’s network. This reconnaissance supports planning for evasion, lateral movement, or targeting blind spots.",
        "remediation": "Limit public exposure of appliance interfaces. Use access controls, VPNs, or IP allowlisting. Ensure NIDS signatures for common recon tools are enabled.",
        "improvements": "Rotate interface ports and obfuscate signatures of web consoles. Track certificate reuse on proxy devices to detect enumeration.",
        "mitre_version": "16.1"
    }
