def get_content():
    return {
        "id": "T1602",  # Tactic Technique ID
        "url_id": "1602",  # URL segment for technique reference
        "title": "Data from Configuration Repository",  # Name of the attack technique
        "description": "Adversaries may collect data from device management systems or SNMP repositories that store sensitive system administration information, including configurations of managed devices.",  # Simple description
        "tags": [
            "Configuration Repository",
            "SNMP",
            "Network Devices",
            "Managed Devices",
            "Discovery",
            "US-CERT-TA18-106A",
            "US-CERT TA17-156A",
            "Cisco Advisory SNMP v3",
            "Cisco Securing SNMP",
            "Cisco Blog Legacy Device Attacks"
        ],  # Up to 10 tags
        "tactic": "Collection",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "Network",  # Targeted environment
        "tips": [
            "Monitor network traffic to detect unauthorized queries for device configurations",
            "Use secure SNMP configurations (e.g., SNMPv3 with authentication and encryption)",
            "Restrict access to configuration management services via network segmentation and ACLs"
        ],
        "data_sources": "Network Traffic: Network Connection Creation, Network Traffic: Network Traffic Content",
        "log_sources": [
            {
                "type": "Network Traffic",
                "source": "Flow Data or Packet Capture",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Configuration Data",
                "location": "Management systems or SNMP repositories",
                "identify": "Device configurations, credentials, and other sensitive info"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Extracted Data",
                "location": "Adversary-controlled system or storage",
                "identify": "Exfiltrated configuration details"
            }
        ],
        "detection_methods": [
            "Analyze SNMP traffic for unusual or unauthorized requests",
            "Monitor network logs for unexpected queries from untrusted IP addresses",
            "Look for anomalous connections to configuration management endpoints"
        ],
        "apt": [],
        "spl_query": [],
        "hunt_steps": [
            "Identify systems hosting configuration repositories and log all requests",
            "Check for SNMP or management traffic from unknown sources",
            "Correlate device configuration access with user accounts or processes"
        ],
        "expected_outcomes": [
            "Detection of unauthorized attempts to retrieve device configurations",
            "Identification of suspicious SNMP or management traffic patterns",
            "Reduced risk of large-scale data exfiltration from configuration repositories"
        ],
        "false_positive": "Legitimate network monitoring tools or administrative scripts may query SNMP or management systems. Validate authorized usage and scheduling.",
        "clearing_steps": [
            "Disable or remove unauthorized SNMP or management tool access",
            "Enforce secure SNMP configurations (e.g., strong authentication, encryption)",
            "Update and rotate credentials for configuration management interfaces"
        ],
        "mitre_mapping": [
            {
                "tactic": "Collection",
                "technique": "Data from Configuration Repository (T1602)",
                "example": "Collecting device configurations via SNMP or management systems"
            }
        ],
        "watchlist": [
            "Suspicious or frequent SNMP GET/SET requests",
            "Unusual connection attempts to legacy or unpatched devices",
            "Large volumes of configuration data transmitted to unknown hosts"
        ],
        "enhancements": [
            "Implement multi-factor authentication for management interfaces",
            "Use SNMPv3 with strong cryptographic options and limit access by IP",
            "Regularly audit device configuration repositories for unauthorized changes"
        ],
        "summary": "Adversaries can target configuration repositories to collect large amounts of sensitive system administration data, often through SNMP or other management protocols.",
        "remediation": "Secure configuration management endpoints, use encrypted protocols (SNMPv3), and monitor logs for unauthorized queries or unusual traffic patterns.",
        "improvements": "Regularly patch and update devices, restrict management traffic via network segmentation, and conduct frequent reviews of SNMP and device configuration permissions."
    }
