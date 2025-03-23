def get_content():
    return {
        "id": "T1011.001",
        "url_id": "T1011/001",
        "title": "Exfiltration Over Other Network Medium: Exfiltration Over Bluetooth",
        "description": "Adversaries may exfiltrate data over Bluetooth rather than using the primary command and control channel, especially when the Bluetooth interface is less monitored.",
        "tags": ["exfiltration", "bluetooth", "covert channel", "wireless", "alternate channel", "data theft"],
        "tactic": "Exfiltration",
        "protocol": "Bluetooth",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor for unusual use of Bluetooth adapters, especially from unexpected processes",
            "Track creation of new network interfaces or adapter configuration changes",
            "Alert on use of `hcitool`, `bluetoothctl`, or Windows Bluetooth API access outside of normal user behavior"
        ],
        "data_sources": "Command, File, Network Traffic",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Network Connections", "location": "/var/log/syslog or Windows Event Logs", "identify": "Bluetooth pairing or connection logs"},
            {"type": "Process List", "location": "System process listing", "identify": "Unexpected processes using Bluetooth modules"},
            {"type": "Environment Variables", "location": "BT_CONFIG or related settings", "identify": "Environment changes related to Bluetooth behavior"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor for new Bluetooth devices or active communication channels",
            "Track unusual or unauthorized access to Bluetooth APIs or drivers",
            "Use endpoint behavior analytics to detect passive Bluetooth exfiltration"
        ],
        "apt": [
            "Beetlejuice"
        ],
        "spl_query": [
            'index=os_logs (command_line="*bluetoothctl*" OR command_line="*hcitool*" OR command_line="*rfcomm*")',
            'index=network_logs protocol="bluetooth" OR adapter_name="hci*"'
        ],
        "hunt_steps": [
            "Identify all Bluetooth-capable devices within the environment",
            "Correlate Bluetooth traffic with known endpoints and business devices",
            "Review logs for historical connections to unfamiliar MAC addresses"
        ],
        "expected_outcomes": [
            "Detection of data exfiltration attempts over Bluetooth",
            "Identification of unauthorized Bluetooth interface usage"
        ],
        "false_positive": "Legitimate Bluetooth usage (e.g., headsets, keyboards) may trigger alerts. Correlate with user, time of day, and device fingerprint.",
        "clearing_steps": [
            "Disable unauthorized Bluetooth interfaces",
            "Remove rogue Bluetooth devices from trusted device lists",
            "Revoke credentials or isolate endpoints used for exfiltration"
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1095", "example": "Bluetooth used for alternate exfiltration channel bypassing corporate proxy"}
        ],
        "watchlist": [
            "Unexpected processes communicating via Bluetooth",
            "Use of system utilities to initiate or pair Bluetooth connections",
            "High-volume file access followed by outbound Bluetooth activity"
        ],
        "enhancements": [
            "Limit Bluetooth adapter permissions by group policy or configuration management",
            "Deploy Bluetooth traffic monitoring on endpoint EDR or system-level logs",
            "Blacklist unnecessary Bluetooth drivers or modules"
        ],
        "summary": "Bluetooth can be abused for covert data exfiltration, especially when enterprise defenses focus on internet-bound traffic. Adversaries may exploit nearby receivers to bypass perimeter controls.",
        "remediation": "Enforce strict control and monitoring over Bluetooth device use. Disable unused wireless interfaces and alert on configuration changes.",
        "improvements": "Deploy host-based firewall or EDR controls for wireless communication. Monitor for anomalous interface usage during non-working hours.",
        "mitre_version": "16.1"
    }
