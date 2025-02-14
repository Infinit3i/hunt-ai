def get_content():
    return {
        "id": "T1048.003",
        "url_id": "T1048/003",
        "title": "Encrypted Outbound Connections",
        "tactic": "Exfiltration",
        "data_sources": "Firewall, Proxy, NetFlow, DNS, PCAP, Endpoint Logs",
        "protocol": "HTTPS, TLS, SSL, TCP",
        "os": "Platform Agnostic",
        "objective": "Detect and investigate suspicious encrypted outbound connections that may indicate data exfiltration, command-and-control (C2) traffic, or malicious tunneling over SSL/TLS.",
        "scope": "Monitor outbound encrypted traffic for anomalies in SSL certificate details, unusual destination domains, and traffic spikes.",
        "threat_model": "Adversaries leverage encrypted outbound traffic to exfiltrate data, establish C2 connections, and bypass security controls by using trusted encryption protocols.",
        "hypothesis": [
            "Are there outbound encrypted connections to known malicious IPs?",
            "Are users connecting to unusual SSL/TLS endpoints?",
            "Do outbound encrypted sessions show abnormal traffic volume spikes?"
        ],
        "log_sources": [
            {"type": "Firewall & Proxy Logs", "source": "Palo Alto, Fortinet, Cisco ASA, Zscaler, Bluecoat"},
            {"type": "NetFlow & PCAP Logs", "source": "Zeek (Bro), Cisco NetFlow, Suricata, Wireshark"},
            {"type": "DNS Logs", "source": "Microsoft DNS, OpenDNS, Cisco Umbrella"},
            {"type": "Endpoint Security Logs", "source": "CrowdStrike, Defender ATP detecting suspicious TLS activity"},
            {"type": "Threat Intelligence Feeds", "source": "VirusTotal, AbuseIPDB, AlienVault OTX"}
        ],
        "detection_methods": [
            "Monitor outbound HTTPS/TLS traffic to detect unusual SSL certificates.",
            "Detect high-volume encrypted traffic to new or unexpected destinations.",
            "Identify long-duration TLS sessions that may indicate tunneling or persistent C2 communication.",
            "Correlate encrypted outbound connections with known malicious IPs and domains."
        ],
        "expected_outcomes": [
            "Suspicious Encrypted Traffic Detected: Block outbound connections to known malicious IPs/domains. Investigate compromised endpoints for malware or C2 activity.",
            "No Malicious Activity Found: Improve baseline monitoring of encrypted traffic patterns. Strengthen SSL/TLS inspection policies and anomaly detection."
        ],
        "mitre_mapping": [
            {"tactic": "Command & Control", "technique": "T1095 (Non-Standard Port Usage)", "example": "Malware may use alternative ports (e.g., 8443, 8080) for encrypted C2."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Attackers may transfer compressed files over HTTPS tunnels."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Adversaries may delete logs to erase evidence of encrypted C2."},
            {"tactic": "Lateral Movement", "technique": "T1021.001 (Remote Desktop Protocol)", "example": "Attackers may pivot internally after establishing encrypted C2."},
            {"tactic": "Persistence", "technique": "T1098 (Account Manipulation)", "example": "Adversaries may create accounts for long-term encrypted access."}
        ]
    }
