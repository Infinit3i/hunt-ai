def get_content():
    return {
        "id": "T1049",
        "url_id": "T1049",
        "title": "System Network Connections Discovery",
        "description": "Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network. An adversary who gains access to a system in a cloud-based environment may map out Virtual Private Clouds or Virtual Networks to determine connected systems and services. The actions performed are similar regardless of the operating system but may provide information about the networked cloud environment. Adversaries may use utilities and commands such as 'netstat', 'net use', and 'net session' with Net, or 'lsof', 'who -a', and 'w' on macOS and Linux. Network device commands like 'show ip sockets' may also be used.",
        "tags": ["Discovery", "Network", "Cloud", "Network Connections"],
        "tactic": "Discovery",
        "protocol": "",
        "os": "IaaS, Linux, Network, Windows, macOS",
        "tips": ["Monitor processes and command-line arguments for actions that could gather system and network information.", "Monitor CLI activity for unexpected or unauthorized command use from non-standard users or locations."],
        "data_sources": "Command: Command Execution, Process: OS API Execution, Process: Process Creation",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "Process", "source": "OS API Execution", "destination": ""},
            {"type": "Process", "source": "Process Creation", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Process", "location": "Process Creation", "identify": "Commands executed to discover network connections such as netstat or lsof"}
        ],
        "destination_artifacts": [
            {"type": "Network Traffic", "location": "Network Connection Creation", "identify": "Network connections established or discovered"}
        ],
        "detection_methods": ["Monitor for the use of network discovery commands or unexpected network connection queries.", "Analyze process creation logs for discovery-related tools such as 'netstat', 'net use', and 'lsof'."],
        "apt": ["Dtrack", "BlackEnergy", "Lizar", "QakBot", "Metador", "Tropic Trooper", "Muddy Water", "Turla", "Maze", "Cobalt Strike", "Mandiant APT1", "SolarWinds", "Triton"],
        "spl_query": [],
        "hunt_steps": ["Look for signs of network scanning or querying for system information like IPs and services.", "Analyze logs for processes invoking network discovery commands or similar tools."],
        "expected_outcomes": ["Detection of unauthorized network scanning or mapping behavior", "Identification of remote and local system connections."],
        "false_positive": "Legitimate network diagnostics or administrative actions may trigger discovery events.",
        "clearing_steps": ["Terminate any suspicious network discovery processes and block any unauthorized access.", "Audit and restrict access to network discovery tools for non-administrative users."],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1049", "example": "Adversary uses 'netstat' or similar tools to list active network connections on a target system"}
        ],
        "watchlist": ["Monitor for the execution of network discovery commands in unexpected locations or from non-standard users."],
        "enhancements": ["Use behavioral analysis to detect anomalous network connection patterns that deviate from normal traffic flows."],
        "summary": "System Network Connections Discovery allows adversaries to map out system network connections to identify targets for lateral movement and other attack activities.",
        "remediation": "Monitor for suspicious network discovery activities and limit the use of network discovery tools to trusted administrative users.",
        "improvements": "Enhance detection by improving the ability to distinguish between benign and malicious use of network connection discovery tools.",
        "mitre_version": "16.1"
    }
