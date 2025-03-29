def get_content():
    return {
        "id": "T1205",
        "url_id": "T1205",
        "title": "Traffic Signaling",
        "description": "Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control.",
        "tags": ["Command and Control", "Defense Evasion", "Persistence", "Traffic Signaling", "Port Knocking", "Wake-on-LAN", "Custom Protocols"],
        "tactic": "Command and Control",
        "protocol": "ICMP, DNS, TCP, HTTP, HTTPS, Wake-on-LAN, Custom",
        "os": "Windows, Linux, macOS, Network",
        "tips": [
            "Enable full packet capture or NetFlow for sensitive network segments.",
            "Look for unusual sequences of failed connection attempts (e.g., port knocking).",
            "Harden device firmware and image management to prevent backdoor implants."
        ],
        "data_sources": "Network Traffic, Process",
        "log_sources": [
            {"type": "Network Traffic", "source": "Zeek, Suricata, Wireshark", "destination": ""},
            {"type": "Network Traffic", "source": "Firewall/Router Logs", "destination": ""},
            {"type": "Process", "source": "Sysmon (Event ID 3, 22)", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Firewall Configuration", "location": "Host Firewall or Network Appliance", "identify": "Rules altered dynamically after knock signal"},
            {"type": "pcap", "location": "Packet Capture Storage", "identify": "Encoded or patterned signaling traffic"}
        ],
        "destination_artifacts": [
            {"type": "Open Ports", "location": "Firewall or Port Table", "identify": "Ports opened dynamically post-signal"},
            {"type": "Process Execution", "location": "System Memory", "identify": "Triggered malware post-signal via libpcap or raw sockets"}
        ],
        "detection_methods": [
            "Monitor traffic for port knocking or crafted packet sequences",
            "Detect Wake-on-LAN magic packets on internal subnets",
            "Use packet timing and entropy analysis to identify covert signaling"
        ],
        "apt": [
            "Turla", "Iron Tiger", "Kobalos", "Snake Malware", "Winnti", "Cd00r", "Synful Knock"
        ],
        "spl_query": [
            "index=network (protocol=icmp OR protocol=dns OR port IN (0,1,7,9,65535))\n| stats count by src_ip, dest_ip, port, _time",
            "index=firewall_logs port!=80 port!=443 port!=53 action=allowed\n| stats count by src_ip, dest_ip, port"
        ],
        "hunt_steps": [
            "Inspect sequential failed port connections from the same source (knocking)",
            "Detect network packets with unusually high entropy in the payload",
            "Search for signs of pcap or raw socket sniffing libraries in binaries"
        ],
        "expected_outcomes": [
            "Identification of backdoor triggers or stealthy command/control traffic",
            "Detection of dynamic port manipulation based on signal packet sequences"
        ],
        "false_positive": "Misconfigured scanning tools or legitimate custom protocol software may mimic signaling behavior.",
        "clearing_steps": [
            "Reset firewall configurations to default and audit changes",
            "Isolate affected systems and analyze for implanted services or hidden listeners",
            "Re-image impacted embedded systems or routers after firmware validation"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-network-compromise"
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1601.001", "example": "Backdoor embedded in patched system image awaiting signal"},
            {"tactic": "Defense Evasion", "technique": "T1036", "example": "Custom listener using raw sockets camouflaged under legitimate ports"},
            {"tactic": "Command and Control", "technique": "T1205", "example": "Adversary sends crafted packet sequence to activate malware functionality"}
        ],
        "watchlist": [
            "Wake-on-LAN activity on non-administrative networks",
            "Repeated connection attempts to closed ports",
            "Suspicious packet header manipulation or unused protocols"
        ],
        "enhancements": [
            "Implement Suricata signatures for known port-knocking sequences",
            "Use Zeek to correlate sequential closed port accesses",
            "Incorporate threat intelligence feeds for custom signaling IOC indicators"
        ],
        "summary": "Traffic signaling techniques enable stealthy command and control or activation of hidden capabilities, often through covert packet sequences or payload content that only the malware recognizes.",
        "remediation": "Audit and reset dynamic firewall rules, monitor embedded systems, and isolate endpoints demonstrating unusual traffic triggering behaviors.",
        "improvements": "Enrich detection logic with behavioral and timing analysis, monitor unassigned ports, and deploy firmware integrity tools.",
        "mitre_version": "16.1"
    }
