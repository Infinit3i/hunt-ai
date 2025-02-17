def get_content():
    """
    Returns structured content for the Network Sniffing technique (T1040).
    """
    return {
        "id": "T1040",
        "url_id": "T1040",
        "title": "Network Sniffing",
        "tactic": "Credential Access",
        "data_sources": "Packet Capture, Network Traffic Analysis, Host Monitoring",
        "protocol": "Multiple",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries use network sniffing to capture sensitive data in transit, such as credentials or confidential communications.",
        "scope": "Monitor for unauthorized packet capture activities and analyze network traffic for anomalies.",
        "threat_model": "Adversaries may deploy network sniffers on compromised systems to intercept and extract sensitive data from network traffic.",
        "hypothesis": [
            "Are there unauthorized packet capture tools running on endpoints?",
            "Is there unexpected network traffic analysis occurring on the network?",
            "Are adversaries attempting to extract credentials from network traffic?"
        ],
        "tips": [
            "Monitor for known network sniffing tools such as Wireshark, tcpdump, and NetworkMiner.",
            "Detect promiscuous mode network interfaces that indicate sniffing behavior.",
            "Analyze process execution logs for unauthorized use of packet capture utilities."
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "Packet Capture", "destination": "Network Logs"},
            {"type": "Process Monitoring", "source": "Sysmon Event ID 1", "destination": "Endpoint Logs"}
        ],
        "source_artifacts": [
            {"type": "Process Execution", "location": "C:\\Program Files", "identify": "wireshark.exe, tcpdump.exe"}
        ],
        "destination_artifacts": [
            {"type": "Network Traffic Logs", "location": "/var/logs/network/", "identify": "Captured packets with credentials"}
        ],
        "detection_methods": [
            "Monitor for execution of network sniffing tools.",
            "Detect network interfaces placed in promiscuous mode.",
            "Analyze DNS traffic for domains commonly associated with sniffing tools."
        ],
        "apt": ["G0080", "G0069"],
        "spl_query": [
            "index=network_logs eventType=PacketCapture | table time, sourceIP, destinationIP, toolUsed"
        ],
        "hunt_steps": [
            "Identify endpoints running packet capture tools.",
            "Analyze network traffic logs for anomalies indicative of sniffing.",
            "Investigate unauthorized network monitoring activities."
        ],
        "expected_outcomes": [
            "Detection of unauthorized network sniffing activities.",
            "No suspicious activity found, improving network security baselines."
        ],
        "false_positive": "Network administrators may use packet capture tools for legitimate troubleshooting purposes.",
        "clearing_steps": [
            "Disable unauthorized packet capture tools.",
            "Enforce network security policies to prevent unauthorized monitoring."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1557 (Adversary-in-the-Middle)", "example": "Interception of network traffic for credential harvesting."}
        ],
        "watchlist": [
            "Monitor network for unusual spikes in packet capture activities.",
            "Detect unauthorized execution of sniffing tools on endpoints."
        ],
        "enhancements": [
            "Implement network segmentation to limit exposure of sensitive data.",
            "Deploy endpoint detection tools to detect unauthorized network monitoring."
        ],
        "summary": "Network sniffing is used by adversaries to capture sensitive information from network traffic, posing a risk to credentials and communications.",
        "remediation": "Remove unauthorized network sniffing tools and apply least-privilege principles to restrict network monitoring.",
        "improvements": "Enhance logging of network packet captures and implement stricter endpoint security controls."
    }
