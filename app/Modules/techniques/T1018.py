def get_content():
    return {
        "id": "T1018",
        "url_id": "T1018",
        "title": "Remote System Discovery",
        "description": "Adversaries may attempt to identify other systems on the network that can be used for lateral movement.",
        "tags": ["discovery", "network scan", "remote systems", "net view", "ping", "tracert", "arp", "hosts file"],
        "tactic": "Discovery",
        "protocol": "ICMP, SMB, ARP",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Correlate system events with scanning behavior (e.g., net view, ping sweeps).",
            "Monitor for access to local files like hosts or ARP cache in a discovery context.",
            "Look for recon behavior post-compromise prior to lateral movement."
        ],
        "data_sources": "Sysmon, Command, File, Network Traffic, Process",
        "log_sources": [
            {"type": "Sysmon", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Process List", "location": "Sysmon Event ID 1", "identify": "ping.exe, net.exe, tracert.exe, nbtscan"},
            {"type": "File Access Times (MACB Timestamps)", "location": "C:\\Windows\\System32\\drivers\\etc\\hosts", "identify": "hosts file access"},
            {"type": "DNS Cache", "location": "ipconfig /displaydns or registry", "identify": "target hostname discovery"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Sysmon Event ID 3 or firewall logs", "identify": "lateral discovery traffic"},
            {"type": "Event Logs", "location": "Windows Security or Sysmon", "identify": "recon tools execution from suspicious users"},
            {"type": "Registry Hives", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters", "identify": "NetBIOS enumeration behavior"}
        ],
        "detection_methods": [
            "Alert on use of net view, arp -a, and ping sweeps from non-admin users",
            "Monitor high volume of outbound ICMP or SMB connection attempts",
            "Flag access to hosts/ARP file shortly before remote connection activity"
        ],
        "apt": ["APT10", "FIN6", "Wizard Spider", "QakBot", "BlackCat", "Emissary Panda", "BRONZE SILHOUETTE"],
        "spl_query": [
            'index=sysmon EventCode=1 \n| search CommandLine="*net view*" OR CommandLine="*ping*" OR CommandLine="*tracert*"',
            'index=sysmon EventCode=3 \n| stats count by SourceIp, DestinationIp, DestinationPort \n| where count > 50',
            'index=osquery \n| search path="C:\\Windows\\System32\\drivers\\etc\\hosts" action="read"'
        ],
        "hunt_steps": [
            "Look for repeated ICMP traffic toward multiple internal IPs",
            "Correlate net.exe or nbtscan use with immediate authentication attempts",
            "Review command history or PowerShell logs for recon activity"
        ],
        "expected_outcomes": [
            "Discovery of accessible systems on the local network",
            "Identification of target IPs for lateral movement",
            "Enumeration of network layout for post-exploitation planning"
        ],
        "false_positive": "IT staff or automated asset discovery tools may use similar behavior. Investigate user context and timing of discovery activity.",
        "clearing_steps": [
            "Clear system command history: del /f /q %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt",
            "Delete ARP cache: arp -d *",
            "Remove host file entries if modified by attacker"
        ],
        "mitre_mapping": [
            {"tactic": "Lateral Movement", "technique": "T1021.002", "example": "Adversary pivots using discovered IPs via SMB"},
            {"tactic": "Credential Access", "technique": "T1552.001", "example": "Access to known systems enables credential extraction from memory"}
        ],
        "watchlist": [
            "net.exe, arp.exe, ping.exe usage from non-IT user accounts",
            "host file access correlated with unexpected SMB or RDP connections",
            "High-volume ICMP traffic to sequential IP ranges"
        ],
        "enhancements": [
            "Apply baselining to discovery command frequency per host",
            "Flag scanning commands executed from uncommon directories",
            "Integrate alerts on ping/tracert/net view with user account risk levels"
        ],
        "summary": "Remote System Discovery is used by adversaries to find other hosts on the network to facilitate lateral movement and access expansion.",
        "remediation": "Apply principle of least privilege, limit use of network discovery tools to IT users, and monitor command usage closely.",
        "improvements": "Enhance network segmentation to restrict lateral discovery. Use honeypots to detect unauthorized host enumeration.",
        "mitre_version": "16.1"
    }
