def get_content():
    return {
        "id": "T1590.004",
        "url_id": "T1590/004",
        "title": "Gather Victim Network Information: Network Topology",
        "description": "Adversaries may gather information about the victim's network topology that can be used during targeting. Information about network topologies may include a variety of details, including the physical and/or logical arrangement of both external-facing and internal network environments. This information may also include specifics regarding network devices (gateways, routers, etc.) and other infrastructure. Adversaries may gather this information in various ways, such as direct collection actions via Active Scanning or Phishing for Information. Information about network topologies may also be exposed to adversaries via online or other accessible data sets. Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and/or initial access.",
        "tags": ["reconnaissance", "network-topology", "targeting"],
        "tactic": "Reconnaissance",
        "protocol": "TCP/IP",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Monitor for unusual network scans and traffic patterns",
            "Use honeypots to detect unauthorized reconnaissance",
            "Limit exposure of internal network details to the public"
        ],
        "data_sources": "Network Traffic, Internet Scan, Asset, Command",
        "log_sources": [
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "Asset", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "DNS Cache", "location": "%SystemRoot%\\System32\\dns", "identify": "Contains queried network names"},
            {"type": "Browser History", "location": "AppData\\Local\\Google\\Chrome\\User Data\\Default", "identify": "Accessed infrastructure URLs"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "System Logs", "identify": "Outbound scans or connections"},
            {"type": "Sysmon Logs", "location": "Event ID 3", "identify": "Outbound network connections from reconnaissance tools"}
        ],
        "detection_methods": [
            "Detect external scanning behavior using IDS/IPS or firewall logs",
            "Correlate outbound connections with asset inventory and usage",
            "Monitor access to documentation portals and internal network maps"
        ],
        "apt": ["FIN13", "Volt Typhoon"],
        "spl_query": [
            "index=network\n| search src_ip!=internal_cidr dest_ip=internal_cidr\n| stats count by src_ip, dest_ip, dest_port",
            "index=sysmon EventCode=3\n| search Image=*nmap* OR Image=*masscan* OR Image=*netcat*\n| stats count by Image, SourceIp, DestinationIp"
        ],
        "hunt_steps": [
            "Review outbound connections from atypical workstations",
            "Investigate access to internal network topology documentation",
            "Look for scanning or crawling tool signatures in proxy or firewall logs"
        ],
        "expected_outcomes": [
            "Identification of internal network topology reconnaissance attempts",
            "Correlated events showing enumeration or probing behavior"
        ],
        "false_positive": "Network scans from internal security tools or asset discovery software. Verify tools and schedule with IT.",
        "clearing_steps": [
            "Clear DNS Cache: ipconfig /flushdns",
            "Delete browser history: Run Clear-Content on browser profile folders",
            "Remove Sysmon logs: Stop Sysmon and clear log with wevtutil",
            "Delete artifacts: Remove stored command history and nmap outputs"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "T1583", "example": "Acquire Infrastructure based on known topology"},
            {"tactic": "Initial Access", "technique": "T1133", "example": "Target exposed remote services revealed through topology mapping"}
        ],
        "watchlist": [
            "Access to internal network diagrams",
            "Outbound connections to commonly scanned ports",
            "Execution of network discovery tools on endpoints"
        ],
        "enhancements": [
            "Deploy deception assets to detect scanning",
            "Alert on scanning tool execution from user machines"
        ],
        "summary": "This technique focuses on gathering information related to the layout and components of a target's network, which adversaries may use to plan their next steps such as targeting specific systems, evading detection, or selecting the optimal attack vector.",
        "remediation": "Restrict access to network diagrams and documentation. Employ network segmentation. Use egress filtering to prevent unauthorized scanning and outbound enumeration.",
        "improvements": "Integrate behavior-based detection models to identify unusual scanning or probing behaviors across time and devices.",
        "mitre_version": "16.1"
    }
