def get_content():
    return {
        "id": "T1557.003",  
        "url_id": "T1557/003",  
        "title": "Adversary-in-the-Middle: DHCP Spoofing",  
        "description": "Adversaries may impersonate a DHCP server to redirect network traffic to adversary-controlled infrastructure, enabling network interception and credential theft.",  
        "tags": [
            "DHCP spoofing", "man-in-the-middle attack", "network interception",
            "malicious DHCP server", "traffic manipulation", "rogue DHCP attack",
            "network spoofing", "cyber espionage", "denial of service", "DHCP exhaustion"
        ],  
        "tactic": "Collection, Credential Access",  
        "protocol": "DHCP, IPv4, IPv6, Ethernet",  
        "os": ["Linux", "Windows", "macOS", "Network Devices"],  
        "tips": [
            "Monitor network traffic for rogue DHCP servers distributing malicious configurations.",
            "Detect unauthorized changes in DHCP-assigned DNS and gateway settings.",
            "Monitor for high volumes of DHCP DISCOVER messages, which may indicate DHCP exhaustion attacks."
        ],  
        "data_sources": [
            "Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow",
            "Application Log: DHCP Server Logs", "Intrusion Detection System (IDS) Alerts"
        ],  
        "log_sources": [
            {"type": "Network Logs", "source": "Captured DHCP Packets", "destination": "SIEM"},
            {"type": "System Logs", "source": "DHCP Server Events (Windows EID 1341, 1342, 1020, 1063)", "destination": "Threat Hunting Platform"},
            {"type": "Firewall Logs", "source": "Suspicious DHCP Lease Assignments", "destination": "SOC"}
        ],
        "source_artifacts": [
            {"type": "Packet Capture", "location": "/var/log/dhcp_poison.pcap", "identify": "Malicious DHCP Spoofing Activity"}
        ],
        "destination_artifacts": [
            {"type": "Threat Intelligence", "location": "Adversary-Controlled DHCP Infrastructure", "identify": "Malicious Network Configurations"}
        ],
        "detection_methods": [
            "Monitor for unauthorized DHCP servers operating on the network.",
            "Detect excessive DHCP lease requests, which may indicate DHCP exhaustion attacks.",
            "Identify unexpected changes in assigned network parameters such as DNS and gateway addresses."
        ],
        "apt": ["APT Groups Using DHCP Spoofing", "Malware Utilizing Rogue DHCP Servers"],  
        "spl_query": [
            "index=network_logs source=/var/log/dhcp_poison.pcap \"Suspicious DHCP Activity\"\n| table _time, Source_IP, Destination_IP, DHCP_Changes"
        ],  
        "hunt_steps": [
            "Identify rogue DHCP servers issuing malicious network configurations.",
            "Monitor for abnormal changes in DHCP logs indicating potential spoofing.",
            "Investigate repeated unsolicited DHCP responses from unauthorized devices."
        ],  
        "expected_outcomes": [
            "Detection of adversary-in-the-middle attacks leveraging DHCP spoofing.",
            "Early identification of unauthorized DHCP configurations and network redirection."
        ],  
        "false_positive": "Legitimate changes in DHCP server settings due to maintenance or upgrades.",  
        "clearing_steps": [
            "Reconfigure affected DHCP settings to remove adversary-controlled network parameters.",
            "Implement DHCP snooping on network devices to prevent unauthorized DHCP servers."
        ],  
        "mitre_mapping": [
            {"tactic": "Collection, Credential Access", "technique": "Adversary-in-the-Middle - DHCP Spoofing", "example": "Using a rogue DHCP server to redirect network traffic for credential theft."}
        ],  
        "watchlist": [
            "Known DHCP spoofing tools such as Yersinia, DHCPig, and Rogue DHCP Server.",
            "IPs and MAC addresses linked to adversary-controlled DHCP spoofing campaigns."
        ],  
        "enhancements": [
            "Enable DHCP snooping and filtering to block unauthorized DHCP responses.",
            "Use static IP addressing or authorized DHCP lists to mitigate spoofing risks."
        ],  
        "summary": "Adversaries exploit DHCP spoofing techniques to redirect network traffic, intercept communications, and facilitate credential theft.",  
        "remediation": "Monitor DHCP activity, enforce security controls, and use secure DHCP configurations to prevent DHCP-based attacks.",  
        "improvements": "Implement network segmentation and zero-trust security models to reduce DHCP spoofing risks."  
    }
