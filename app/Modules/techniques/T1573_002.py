def get_content():
    return {
        "id": "T1573.002",
        "url_id": "T1573/002",
        "title": "Encrypted Channel: Asymmetric Cryptography",
        "tactic": "Command and Control",
        "data_sources": "Network Traffic, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS), SSL/TLS Inspection Logs",
        "protocol": "RSA, ECC, Custom Asymmetric Encryption",
        "os": "Platform Agnostic",
        "objective": "Detect and mitigate adversaries using asymmetric encryption to establish secure command-and-control (C2) channels and evade network detection.",
        "scope": "Identify encrypted traffic patterns using asymmetric encryption algorithms to obfuscate C2 communications.",
        "threat_model": "Adversaries use asymmetric encryption (e.g., RSA, ECC) to secure C2 communications, ensuring only the intended recipient can decrypt messages and preventing security tools from inspecting the traffic.",
        "hypothesis": [
            "Are there unexpected uses of asymmetric encryption in network traffic?",
            "Are adversaries leveraging asymmetric encryption to protect their C2 channels?",
            "Is high-entropy traffic indicative of encrypted malicious communications?"
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "Zeek (Bro), Suricata, Wireshark"},
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA"},
            {"type": "Proxy Logs", "source": "Zscaler, Bluecoat, McAfee Web Gateway"},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 3, 22), EDR (CrowdStrike, Defender ATP)"},
            {"type": "IDS", "source": "Snort, Suricata, Zeek (Bro)"},
            {"type": "SSL/TLS Inspection Logs", "source": "TLS Interception Appliances, Web Proxies"}
        ],
        "detection_methods": [
            "Monitor for high-entropy encrypted traffic over non-standard ports.",
            "Detect asymmetric encryption usage in outbound communications.",
            "Identify connections using custom encryption protocols for C2."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search encryption=*rsa* OR encryption=*ecc* OR encryption=*custom* \n| stats count by src_ip, dest_ip, protocol"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify encrypted C2 traffic using asymmetric encryption.",
            "Analyze Packet Payloads: Inspect high-entropy network traffic.",
            "Monitor for Custom Encryption: Detect adversaries using unique encryption schemes.",
            "Correlate with Threat Intelligence: Compare with known C2 techniques using asymmetric cryptography.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Asymmetric Encrypted C2 Detected: Block malicious encrypted traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for encrypted command-and-control techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1573.002 (Asymmetric Cryptography)", "example": "C2 traffic encrypted via RSA key exchange."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data exfiltrated using ECC-encrypted UDP traffic."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs after encrypted communication."}
        ],
        "watchlist": [
            "Flag high-entropy outbound traffic using asymmetric encryption.",
            "Monitor for anomalies in encrypted communication patterns.",
            "Detect unauthorized use of encryption protocols within internal traffic."
        ],
        "enhancements": [
            "Deploy TLS inspection to analyze encrypted C2 traffic contents.",
            "Implement entropy-based analysis for detecting asymmetric encryption misuse.",
            "Improve correlation between encrypted traffic and known threat actor techniques."
        ],
        "summary": "Document detected malicious encrypted command-and-control activity and affected systems.",
        "remediation": "Block unauthorized encrypted communications, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of encrypted channel-based command-and-control techniques."
    }
