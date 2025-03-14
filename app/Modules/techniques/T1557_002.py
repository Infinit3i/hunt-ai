def get_content():
    return {
        "id": "T1557.002",  
        "url_id": "T1557/002",  
        "title": "Adversary-in-the-Middle: ARP Cache Poisoning",  
        "description": "Adversaries may manipulate ARP caches to intercept and redirect network traffic between devices, enabling data collection and manipulation.",  
        "tags": [
            "ARP cache poisoning", "man-in-the-middle attack", "network interception",
            "packet sniffing", "traffic manipulation", "gratuitous ARP attack",
            "network spoofing", "cyber espionage", "credential theft"
        ],  
        "tactic": "Collection, Credential Access",  
        "protocol": "ARP, IPv4, Ethernet",  
        "os": ["Linux", "Windows", "macOS", "Network Devices"],  
        "tips": [
            "Monitor network traffic for unusual ARP requests and responses.",
            "Detect multiple IP addresses mapping to the same MAC address, indicating ARP poisoning.",
            "Analyze logs for unsolicited gratuitous ARP announcements from untrusted sources."
        ],  
        "data_sources": [
            "Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow",
            "System Logs: ARP Table Changes", "Intrusion Detection System (IDS) Alerts"
        ],  
        "log_sources": [
            {"type": "Network Logs", "source": "Captured ARP Packets", "destination": "SIEM"},
            {"type": "Endpoint Logs", "source": "ARP Table Modifications", "destination": "Threat Hunting Platform"},
            {"type": "Firewall Logs", "source": "Suspicious MAC Address Spoofing", "destination": "SOC"}
        ],
        "source_artifacts": [
            {"type": "Packet Capture", "location": "/var/log/arp_poison.pcap", "identify": "Malicious ARP Spoofing Activity"}
        ],
        "destination_artifacts": [
            {"type": "Threat Intelligence", "location": "Adversary-Controlled ARP Spoofing Infrastructure", "identify": "Malicious MAC Addresses"}
        ],
        "detection_methods": [
            "Monitor for multiple IP addresses mapping to a single MAC address.",
            "Detect excessive ARP requests and responses from a single source.",
            "Identify unexpected network gateway changes indicative of ARP poisoning."
        ],
        "apt": ["LuminousMoth", "Cleaver", "APT Groups Using ARP Spoofing"],  
        "spl_query": [
            "index=network_logs source=/var/log/arp_poison.pcap \"Suspicious ARP Activity\"\n| table _time, Source_IP, Destination_IP, ARP_Changes"
        ],  
        "hunt_steps": [
            "Identify adversary-controlled IPs or MAC addresses performing ARP spoofing.",
            "Monitor for abnormal ARP cache modifications across endpoints.",
            "Investigate repeated unsolicited ARP responses from a specific network source."
        ],  
        "expected_outcomes": [
            "Detection of adversary-in-the-middle attacks leveraging ARP cache poisoning.",
            "Early identification of traffic interception and unauthorized network access."
        ],  
        "false_positive": "Legitimate network diagnostics or ARP table refresh events.",  
        "clearing_steps": [
            "Flush and rebuild ARP caches to remove malicious entries.",
            "Implement Dynamic ARP Inspection (DAI) on network devices to block spoofed ARP packets."
        ],  
        "mitre_mapping": [
            {"tactic": "Collection, Credential Access", "technique": "Adversary-in-the-Middle - ARP Cache Poisoning", "example": "Using ARP spoofing to intercept and manipulate network traffic."}
        ],  
        "watchlist": [
            "Known ARP spoofing tools such as Ettercap, Bettercap, and ARPspoof.",
            "IPs and MAC addresses linked to adversary-controlled ARP manipulation campaigns."
        ],  
        "enhancements": [
            "Enable ARP monitoring with IDS/IPS solutions to detect anomalies.",
            "Use cryptographic network authentication to mitigate ARP spoofing attacks."
        ],  
        "summary": "Adversaries exploit ARP cache poisoning techniques to manipulate network traffic, steal credentials, and intercept communications.",  
        "remediation": "Monitor ARP activity, implement security controls, and use secure communication protocols to prevent ARP-based attacks.",  
        "improvements": "Deploy network segmentation and zero-trust security models to reduce ARP spoofing risks."  
    }
