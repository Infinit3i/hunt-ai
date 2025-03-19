def get_content():
    return {
        "id": "T1584.008",  # Tactic Technique ID
        "url_id": "1584/008",  # URL segment for technique reference
        "title": "Compromise Infrastructure: Network Devices",  # Name of the attack technique
        "description": "Adversaries may compromise third-party network devices (e.g., SOHO routers) to host malicious payloads, facilitate phishing campaigns, harvest credentials, or provide a proxy for subsequent operations such as Command and Control.",
        "tags": [
            "network device compromise",
            "router compromise",
            "resource development",
            "C2",
            "botnet",
            "phishing"
        ],
        "tactic": "Resource Development",  # Associated MITRE ATT&CK tactic
        "protocol": "Various network protocols",  # Protocol used in the attack technique
        "os": "N/A",  # Targeted operating systems (network appliances)
        "tips": [
            "Monitor for unauthorized device configuration changes or unusual logs.",
            "Implement strong authentication (MFA) and regular firmware updates.",
            "Use intrusion detection/prevention systems to identify suspicious traffic from network devices."
        ],
        "data_sources": "Internet Scan",  # Data sources relevant to detection
        "log_sources": [
            {"type": "Internet Scan", "source": "Response Content", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Configuration file", "location": "Device firmware/config", "identify": "Check for malicious modifications"}
        ],
        "destination_artifacts": [
            {"type": "Network Traffic", "location": "Outbound connections", "identify": "Identify suspicious C2 traffic"}
        ],
        "detection_methods": [
            "Monitor device logs for unauthorized access or changes to firmware/configuration.",
            "Check for known vulnerabilities or exploits targeting specific network devices.",
            "Analyze network traffic for signs of malicious proxying or botnet activity."
        ],
        "apt": [
            "Volt Typhoon",
            "APT31"
        ],
        "spl_query": [
            "index=network \n| stats count by src_ip, dest_ip, device"
        ],
        "hunt_steps": [
            "Scan for unusual administrative logins to network devices.",
            "Compare current firmware and configuration with known good baselines.",
            "Correlate device activity with threat intelligence regarding known exploits or campaigns."
        ],
        "expected_outcomes": [
            "Detection of compromised network devices used as malicious infrastructure.",
            "Identification of unauthorized firmware modifications or suspicious traffic patterns."
        ],
        "false_positive": "Legitimate reconfigurations or authorized firmware updates may appear suspicious; validate changes via administrative logs and approvals.",
        "clearing_steps": [
            "Isolate compromised devices from the network and reset to factory defaults.",
            "Apply latest firmware and security patches.",
            "Change administrative credentials and enable multi-factor authentication.",
            "Reintegrate devices into the network under enhanced monitoring."
        ],
        "mitre_mapping": [
            {
                "tactic": "Command and Control",
                "technique": "Hide Infrastructure (T1665)",
                "example": "Adversaries may pivot from compromised devices to obscure traffic through a proxy or botnet."
            }
        ],
        "watchlist": [
            "Outdated firmware or known vulnerable device models.",
            "Unusual inbound or outbound connections from network device IPs.",
            "Unexpected configuration changes in router or firewall settings."
        ],
        "enhancements": [
            "Implement device-level logging and monitoring solutions.",
            "Leverage intrusion detection systems for anomalous device traffic.",
            "Use certificate-based authentication and strong encryption protocols."
        ],
        "summary": "Adversaries may compromise network devices to gain a foothold for malicious operations, leveraging these devices as proxies, hosting points, or credential harvesting platforms due to their limited defenses.",
        "remediation": "Apply firmware updates, patch known vulnerabilities, enforce strong credentials, segment network devices, and monitor device logs for anomalies.",
        "improvements": "Centralize device logging, integrate threat intelligence for known device exploits, adopt zero-trust segmentation, and regularly audit network appliances for security posture."
    }
