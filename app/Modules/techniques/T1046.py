def get_content():
    return {
        "id": "T1046",
        "url_id": "T1046",
        "title": "Network Service Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port and/or vulnerability scans using tools that are brought onto a system. Within cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment is connected to an on-premises environment, adversaries may be able to identify services running on non-cloud systems as well. Within macOS environments, adversaries may use the native Bonjour application to discover services running on other macOS hosts within a network.",
        "tags": ["Discovery", "Network Service Discovery", "Service Discovery", "Port Scanning"],
        "tactic": "Discovery",
        "protocol": "",
        "os": "Containers, IaaS, Linux, Network, Windows, macOS",
        "tips": ["Monitor for process use of the networks and inspect intra-network flows to detect port scans.", "System and network discovery techniques normally occur throughout an operation as an adversary learns the environment."],
        "data_sources": "Cloud Service: Cloud Service Enumeration, Command: Command Execution, Network Traffic: Network Traffic Flow",
        "log_sources": [
            {"type": "Cloud Service", "source": "Cloud Service Enumeration", "destination": ""},
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Flow", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Network Traffic", "location": "Network Traffic Flow", "identify": "Port scan or service discovery activity"}
        ],
        "destination_artifacts": [
            {"type": "Network Traffic", "location": "Network Traffic Flow", "identify": "Service information or open ports discovered"}
        ],
        "detection_methods": ["Monitor for scanning activity by examining network traffic for patterns consistent with service discovery", "Use network intrusion detection systems to identify port scanning activity"],
        "apt": ["ZxShell", "Lebanese Cedar", "FireEye Periscope", "TELCO BPO Campaign", "Tropic Trooper", "Valak", "Cobalt Strike", "Trojans", "MuddyWater", "TearDrop", "Mofang", "Higaisa", "Astaroth"],
        "spl_query": [],
        "hunt_steps": ["Search for port scanning and service discovery patterns in network traffic", "Inspect traffic for patterns associated with tools used in service discovery (e.g., mDNS or vulnerability scanners)"],
        "expected_outcomes": ["Identification of service discovery and port scanning activities across the network"],
        "false_positive": "Legitimate network scanning and vulnerability assessments may occasionally be detected as false positives.",
        "clearing_steps": ["Investigate and block scanning tools or malicious traffic associated with unauthorized network discovery", "Ensure that security tools are set up to detect and mitigate such reconnaissance techniques."],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1046", "example": "Scanning for open ports and services running on target systems"}
        ],
        "watchlist": ["Monitor for tools like nmap, netstat, or custom scripts that may indicate service discovery or port scanning attempts"],
        "enhancements": ["Deploy behavioral analysis to detect unusual patterns of network traffic indicative of service discovery", "Enhance detection with machine learning algorithms that flag anomalies in port and service scanning behaviors"],
        "summary": "Network service discovery is used by adversaries to gain information about services running on remote systems, helping to identify exploitable services.",
        "remediation": "Ensure network segmentation, limit access to unnecessary services, and utilize intrusion detection systems to spot service discovery attempts.",
        "improvements": "Increase visibility into intra-network communications and identify any unusual scanning or discovery patterns that could indicate malicious activity.",
        "mitre_version": "16.1"
    }
