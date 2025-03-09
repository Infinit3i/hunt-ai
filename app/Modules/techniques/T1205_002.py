def get_content():
    return {
        "id": "T1205.002",
        "url_id": "T1205/002",
        "title": "Traffic Signaling: Socket Filters",
        "tactic": "Defense Evasion, Persistence, Command and Control",
        "data_sources": "Network Traffic, Firewall Logs, Process Creation Logs, Endpoint Logs, Intrusion Detection Systems (IDS)",
        "protocol": "TCP, UDP, ICMP, Custom Signaling Mechanisms",
        "os": "Linux, Windows, macOS",
        "objective": "Detect and mitigate adversaries using socket filters to monitor network traffic and activate backdoors used for persistence or command and control.",
        "scope": "Identify network traffic patterns and process behaviors indicative of adversaries leveraging socket filters for covert communication and execution triggers.",
        "threat_model": "Adversaries attach socket filters to a network interface to monitor traffic for specific signals. When a crafted packet matching the filter criteria is received, a predefined action is triggered, such as activating a backdoor or launching a reverse shell.",
        "hypothesis": [
            "Are there processes installing socket filters to monitor specific network traffic?",
            "Are adversaries using crafted packets to trigger execution of backdoor commands?",
            "Is there an increase in unexpected network filtering activities on compromised hosts?"
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "Zeek (Bro), Suricata, Wireshark"},
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA"},
            {"type": "Process Creation Logs", "source": "Sysmon (Event ID 1, 10), Linux Auditd, EDR (CrowdStrike, Defender ATP)"},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 3, 22), EDR (CrowdStrike, Defender ATP)"},
            {"type": "IDS", "source": "Snort, Suricata, Zeek (Bro)"}
        ],
        "detection_methods": [
            "Monitor for processes using setsockopt with SO_ATTACH_FILTER options.",
            "Detect applications leveraging libpcap with pcap_setfilter for monitoring traffic.",
            "Identify sudden execution of commands or backdoors following network traffic triggers."
        ],
        "spl_query": [
            "index=endpoint sourcetype=sysmon \n| search process_name=*setsockopt* OR process_name=*pcap_setfilter* \n| stats count by host, process_name, command_line"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify processes attaching socket filters to monitor network traffic.",
            "Analyze Process Creation Logs: Detect anomalies where processes install network filters without authorization.",
            "Monitor for Network Packet-Based Activation: Identify crafted packet sequences triggering execution.",
            "Correlate with Threat Intelligence: Compare with known C2 techniques leveraging socket filters.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Socket Filter-Based C2 Detected: Block malicious socket filter installations and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for socket filter-based C2 techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1205.002 (Socket Filters)", "example": "Adversaries using libpcap to monitor traffic and trigger C2 commands."},
            {"tactic": "Persistence", "technique": "T1547 (Boot or Logon Autostart Execution)", "example": "Socket filters persisting across reboots to re-enable backdoor access."},
            {"tactic": "Command and Control", "technique": "T1205.002 (Socket Filters)", "example": "C2 commands sent via crafted packets to trigger remote execution."}
        ],
        "watchlist": [
            "Flag processes attempting to install socket filters without proper authorization.",
            "Monitor for anomalies in process behavior related to raw network access.",
            "Detect unauthorized applications using network filters for C2 triggers."
        ],
        "enhancements": [
            "Deploy endpoint security controls to restrict unauthorized socket filter installation.",
            "Implement behavioral analytics to detect suspicious network filtering activity.",
            "Improve correlation between socket filter activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious socket filter-based command-and-control activity and affected systems.",
        "remediation": "Block unauthorized socket filter installations, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of socket filter-based command-and-control techniques."
    }
