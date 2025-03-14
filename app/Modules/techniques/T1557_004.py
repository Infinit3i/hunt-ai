def get_content():
    return {
        "id": "T1557.004",
        "url_id": "T1557/004",
        "title": "Adversary-in-the-Middle: Evil Twin",
        "description": "Adversaries may set up fraudulent Wi-Fi access points that mimic legitimate networks to intercept network traffic, capture credentials, and manipulate data.",
        "tags": [
            "Evil Twin Attack", "Wi-Fi Spoofing", "Fake Access Point", "Man-in-the-Middle",
            "Network Interception", "Wireless Attacks", "Wi-Fi Security", "Phishing Over Wi-Fi",
            "Captive Portal Credential Theft", "Malicious Hotspot"
        ],
        "tactic": "Collection, Credential Access",
        "protocol": "Wi-Fi, IEEE 802.11, HTTPS, DNS",
        "os": ["Linux", "Windows", "macOS", "Mobile Devices"],
        "tips": [
            "Use VPNs when connecting to public Wi-Fi to mitigate the risk of Evil Twin attacks.",
            "Enable Wi-Fi security settings that prevent automatic connection to known SSIDs.",
            "Monitor for rogue access points broadcasting legitimate SSIDs with unexpected MAC addresses."
        ],
        "data_sources": [
            "Network Traffic: Network Traffic Content",
            "Network Traffic: Network Traffic Flow",
            "Authentication Logs: Captive Portal Login Attempts"
        ],
        "log_sources": [
            {"type": "Wireless Logs", "source": "Access Point Associations", "destination": "SIEM"},
            {"type": "Network Logs", "source": "DNS Traffic from Public Networks", "destination": "SOC"},
            {"type": "System Logs", "source": "Wi-Fi Connection History", "destination": "Endpoint Detection Platform"}
        ],
        "source_artifacts": [
            {"type": "Packet Capture", "location": "/var/log/evil_twin_traffic.pcap", "identify": "Captured Network Traffic from Rogue Wi-Fi"}
        ],
        "destination_artifacts": [
            {"type": "Threat Intelligence", "location": "Malicious Wi-Fi Infrastructure", "identify": "Adversary-Controlled Wi-Fi Networks"}
        ],
        "detection_methods": [
            "Monitor for duplicate SSIDs with different MAC addresses, which may indicate an Evil Twin attack.",
            "Detect Wi-Fi Pineapple or rogue access points emitting strong, unexpected signals.",
            "Analyze captive portal login attempts for credential phishing attempts."
        ],
        "apt": ["APT Groups Using Evil Twin Attacks", "Threat Actors Deploying Rogue Wi-Fi Networks"],
        "spl_query": [
            "index=network_logs source=/var/log/evil_twin_traffic.pcap \"Suspicious Wi-Fi Activity\"\n| table _time, Source_IP, Destination_IP, SSID_Observed"
        ],
        "hunt_steps": [
            "Identify rogue Wi-Fi access points mimicking legitimate SSIDs.",
            "Analyze probe request traffic to detect adversaries responding to preferred network lists (PNLs).",
            "Investigate abnormal signal strengths and unexpected access point activity."
        ],
        "expected_outcomes": [
            "Detection of adversary-controlled Wi-Fi access points impersonating trusted networks.",
            "Identification of victims connecting to fraudulent Wi-Fi hotspots."
        ],
        "false_positive": "Legitimate Wi-Fi network name changes or temporary public hotspot setup in event locations.",
        "clearing_steps": [
            "Disable auto-connect to known SSIDs on devices to prevent accidental Evil Twin connections.",
            "Use enterprise-grade Wireless Intrusion Prevention Systems (WIPS) to detect and block rogue Wi-Fi access points."
        ],
        "mitre_mapping": [
            {"tactic": "Collection, Credential Access", "technique": "Adversary-in-the-Middle - Evil Twin", "example": "Deploying a rogue Wi-Fi access point to capture user credentials via a fake login page."}
        ],
        "watchlist": [
            "Known tools like Wi-Fi Pineapple, Airbase-ng, and hostapd-karma used in Evil Twin attacks.",
            "Indicators of compromised SSIDs associated with previous attacks."
        ],
        "enhancements": [
            "Deploy 802.1X authentication for Wi-Fi networks to prevent unauthorized access.",
            "Regularly scan for unauthorized access points within corporate environments."
        ],
        "summary": "Evil Twin attacks exploit unprotected or public Wi-Fi networks by deceiving users into connecting to adversary-controlled hotspots, facilitating network interception and data theft.",
        "remediation": "Use strong authentication and encryption on Wi-Fi networks, avoid untrusted access points, and monitor for rogue SSIDs.",
        "improvements": "Implement Wi-Fi security measures such as certificate-based authentication and network segmentation to reduce the impact of Evil Twin attacks."
    }
