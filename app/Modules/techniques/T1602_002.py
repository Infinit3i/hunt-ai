def get_content():
    return {
        "id": "T1602.002",  # Tactic Technique ID
        "url_id": "1602/002",  # URL segment for technique reference
        "title": "Data from Configuration Repository: Network Device Configuration Dump",  # Name of the attack technique
        "description": "Adversaries may access network configuration files to collect sensitive data about the device and network. Attackers can use SNMP, Smart Install, or other management tools to query or export device configurations, revealing information about network layout, software versions, or valid credentials.",  # Simple description
        "tags": [
            "Data from Configuration Repository",
            "Network Device Configuration Dump",
            "SNMP",
            "Smart Install",
            "Legacy Device Attacks",
            "Cisco",
            "US-CERT TA17-156A",
            "US-CERT TA18-106A",
            "Network",
            "Collection"
        ],  # Up to 10 tags
        "tactic": "Collection",  # Associated MITRE ATT&CK tactic
        "protocol": "SNMP, SMI, Various",  # Protocol used in the attack technique
        "os": "Network",  # Targeted environment
        "tips": [
            "Monitor network traffic for unauthorized SNMP/Smart Install requests",
            "Limit device configuration access to trusted management IPs and segments",
            "Enforce SNMPv3 or equivalent secure management protocols with authentication and encryption"
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
                "type": "Network Device Configuration",
                "location": "Managed network devices",
                "identify": "Configuration files containing system or credential data"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Exfiltrated Data",
                "location": "Adversary-controlled system",
                "identify": "Dumped network device configurations"
            }
        ],
        "detection_methods": [
            "Inspect SNMP/Smart Install logs for suspicious or repeated queries",
            "Monitor for large or unusual data transfers from network devices",
            "Use intrusion detection signatures for known configuration file patterns"
        ],
        "apt": [],
        "spl_query": [],
        "hunt_steps": [
            "Identify critical network devices and log all SNMP/Smart Install access attempts",
            "Correlate device configuration exports with user accounts or processes",
            "Search for abnormal access patterns (e.g., repeated attempts to dump configs)"
        ],
        "expected_outcomes": [
            "Detection of unauthorized configuration file retrieval attempts",
            "Identification of suspicious queries or traffic targeting network devices",
            "Prevention of adversaries leveraging config data to further compromise the environment"
        ],
        "false_positive": "Legitimate network administration processes may also dump or back up device configurations. Validate authorized maintenance activity.",
        "clearing_steps": [
            "Disable or restrict unneeded management protocols (e.g., Smart Install)",
            "Migrate to secure SNMPv3 configurations with strong credentials",
            "Rotate device passwords and keys if a compromise is suspected"
        ],
        "mitre_mapping": [
            {
                "tactic": "Collection",
                "technique": "Data from Configuration Repository (T1602)",
                "example": "Using SNMP/Smart Install to retrieve network device configuration files"
            }
        ],
        "watchlist": [
            "Unexpected SNMP GET/SET or Smart Install traffic from unrecognized IPs",
            "Frequent or large transfers of device configuration files",
            "Network devices responding to management protocols not typically used"
        ],
        "enhancements": [
            "Implement multi-factor authentication for device management consoles",
            "Use access control lists to limit SNMP or Smart Install traffic",
            "Regularly audit device configurations for unauthorized changes or suspicious user accounts"
        ],
        "summary": "Adversaries can obtain network device configuration dumps to uncover critical details about network infrastructure, enabling further compromise or credential theft.",
        "remediation": "Secure device management protocols, segment network administration traffic, and routinely audit device configurations and logs to prevent unauthorized access.",
        "improvements": "Adopt SNMPv3 or other secure management standards, restrict management to dedicated VLANs, and continuously monitor for anomalies in device configuration requests."
    }
