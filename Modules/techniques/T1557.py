def get_content():
    return {
        "id": "T1557",
        "url_id": "1557",
        "title": "Adversary-in-the-Middle",
        "tactic": "Credential Access, Collection",
        "data_sources": "Network Traffic, Endpoint Logs, Authentication Logs",
        "protocol": "HTTP, HTTPS, SMB, DNS, ARP",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries intercept and manipulate network traffic to steal credentials and data.",
        "scope": "Monitor network traffic for anomalous interception or manipulation behaviors.",
        "threat_model": "Attackers may position themselves between communications to steal sensitive data, inject malicious payloads, or manipulate authentication sessions.",
        "hypothesis": [
            "Are there unauthorized devices intercepting network traffic?",
            "Are there unexpected changes in authentication behaviors?"
        ],
        "tips": [
            "Monitor for unusual ARP spoofing or DNS poisoning attempts.",
            "Analyze encrypted traffic for anomalies indicating interception.",
            "Check for unauthorized network devices on critical segments."
        ],
        "log_sources": [
            {"type": "Network", "source": "Packet Captures", "destination": "SIEM"},
            {"type": "Endpoint", "source": "Windows Event Logs", "destination": "Endpoint Security Platform"}
        ],
        "source_artifacts": [
            {"type": "Network Capture", "location": "Wireshark Logs", "identify": "Unexpected traffic redirections"},
            {"type": "System Log", "location": "/var/log/syslog", "identify": "Changes in network adapter configurations"}
        ],
        "destination_artifacts": [
            {"type": "Network Traffic", "location": "Firewall Logs", "identify": "Unusual authentication requests"}
        ],
        "detection_methods": [
            "Monitor network traffic for anomalies such as ARP poisoning.",
            "Detect rogue DHCP servers issuing unauthorized network configurations.",
            "Analyze encrypted traffic flows for unexpected certificate mismatches."
        ],
        "apt": [
            "G0094 - Kimsuky: Uses modified versions of PHProxy to examine web traffic."
        ],
        "spl_query": [
            "index=network_logs sourcetype=firewall_logs | search ARP OR DNS spoofing | stats count by src_ip dest_ip"
        ],
        "hunt_steps": [
            "Identify unexpected network devices performing interception activities.",
            "Review logs for rogue authentication attempts or traffic redirection.",
            "Analyze DNS and ARP traffic for signs of poisoning attacks."
        ],
        "expected_outcomes": [
            "Detection of adversaries intercepting network traffic.",
            "Identification of rogue devices performing Man-in-the-Middle attacks."
        ],
        "false_positive": "Some legitimate network management tools may trigger alerts related to ARP or DNS changes. Baseline expected behavior accordingly.",
        "clearing_steps": [
            "Isolate compromised network segments and remove rogue devices.",
            "Enforce strict authentication mechanisms like mutual TLS.",
            "Monitor and filter traffic using IDS/IPS to prevent interception."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1558", "example": "OS Credential Dumping - Adversaries may dump credentials from compromised machines after intercepting authentication data."},
            {"tactic": "Collection", "technique": "T1114", "example": "Email Collection - Intercepted credentials may be used to access and exfiltrate email data."},
            {"tactic": "Exfiltration", "technique": "T1048", "example": "Exfiltration Over Alternative Protocol - Adversaries may use non-standard protocols to exfiltrate captured credentials."}
        ],
        "watchlist": [
            "Suspicious network traffic patterns indicating interception.",
            "Unusual authentication failures due to session hijacking."
        ],
        "enhancements": [
            "Implement encrypted network communications (TLS, VPN).",
            "Deploy network monitoring tools to detect anomalies in traffic patterns."
        ],
        "summary": "Adversaries may position themselves between network communications to intercept sensitive data, steal credentials, or manipulate network traffic for malicious purposes.",
        "remediation": "Enforce encrypted communications, implement network segmentation, and deploy monitoring tools to detect traffic anomalies.",
        "improvements": "Strengthen authentication mechanisms and use secure DNS and ARP protections to mitigate interception risks."
    }