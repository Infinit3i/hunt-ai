def get_content():
    return {
        "id": "T1602.001",  # Tactic Technique ID
        "url_id": "1602/001",  # URL segment for technique reference
        "title": "Data from Configuration Repository: SNMP (MIB Dump)",  # Name of the attack technique
        "description": "Adversaries may target the Management Information Base (MIB) to gather valuable network information from SNMP-managed devices, potentially revealing system data, device configurations, and routing details for further exploitation.",  # Only one pair of quotes for the description
        "tags": [
            "SNMP",
            "MIB Dump",
            "Configuration Repository",
            "Network Management",
            "Network Discovery",
            "Cisco Blog Legacy Device Attacks",
            "US-CERT TA17-156A",
            "US-CERT TA18-106A",
            "Cisco Advisory SNMP v3",
            "SANS InfoSec"
        ],
        "tactic": "Collection",  # Associated MITRE ATT&CK tactic
        "protocol": "SNMP",  # Protocol used in the attack technique
        "os": "Network",  # Targeted environment
        "tips": [
            "Monitor SNMP traffic for unauthorized GET/SET requests or suspicious OIDs",
            "Use SNMPv3 with authentication and encryption to secure MIB access",
            "Restrict SNMP access to trusted hosts/networks and implement ACLs"
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
                "type": "MIB Data",
                "location": "SNMP-managed devices",
                "identify": "Configuration, routing, or interface information"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Exfiltrated Data",
                "location": "Adversary-controlled system",
                "identify": "Collected MIB dumps"
            }
        ],
        "detection_methods": [
            "Analyze SNMP traffic for unusual or repeated requests to MIB objects",
            "Look for SNMP queries from unauthorized IP ranges or devices",
            "Use intrusion detection rules for known SNMP-based scanning or exploitation"
        ],
        "apt": [],  # APT groups known to use this technique
        "spl_query": [],  # Splunk queries to detect the technique
        "hunt_steps": [
            "Identify devices with SNMP enabled and log all GET/SET requests",
            "Correlate SNMP queries with user accounts or processes",
            "Look for anomalies in SNMP usage outside normal business hours"
        ],
        "expected_outcomes": [
            "Detection of unauthorized attempts to query MIB data",
            "Identification of suspicious SNMP traffic from untrusted sources",
            "Discovery of potential network mapping or reconnaissance activity"
        ],
        "false_positive": "Legitimate network monitoring or administration tools may also query MIB data. Verify authorized usage and scheduling.",
        "clearing_steps": [
            "Disable or limit SNMP on devices where it is not needed",
            "Enforce SNMPv3 with strong credentials and encryption",
            "Rotate SNMP community strings or credentials if compromise is suspected"
        ],
        "mitre_mapping": [
            {
                "tactic": "Collection",
                "technique": "Data from Configuration Repository",
                "example": "Using SNMP to retrieve MIB data for device and network info"
            }
        ],
        "watchlist": [
            "Unusual SNMP requests targeting sensitive or rarely used OIDs",
            "Repeated SNMP queries from external or untrusted IPs",
            "High-volume SNMP traffic that deviates from typical baselines"
        ],
        "enhancements": [
            "Implement strict ACLs to limit SNMP queries to known management hosts",
            "Enable logging and alerting for SNMP GET/SET operations",
            "Use device segmentation or dedicated VLANs for network management traffic"
        ],
        "summary": "By dumping MIB data via SNMP, adversaries can obtain detailed network insights, including system configurations, routing tables, and interface details, which can aid in subsequent attacks.",
        "remediation": "Configure SNMP securely (SNMPv3), restrict access to trusted IPs, and regularly audit logs for suspicious SNMP activity.",
        "improvements": "Implement multi-factor authentication where possible for device management, maintain strict network segmentation, and frequently update device firmware to address SNMP-related vulnerabilities."
    }
