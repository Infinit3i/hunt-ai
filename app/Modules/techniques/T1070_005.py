def get_content():
    return {
        "id": "T1070.005",
        "url_id": "T1070/005",
        "title": "Indicator Removal on Host: Network Connection Removal",
        "tactic": "Defense Evasion",
        "data_sources": "Network Traffic Logs, Process Creation Logs, Endpoint Logs, Security Monitoring Tools",
        "protocol": "Firewall Rules, Network Configuration Changes, VPN Manipulation",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries removing network connections to evade detection and prevent forensic investigation.",
        "scope": "Identify suspicious network manipulation activities that indicate an attempt to disrupt monitoring and response.",
        "threat_model": "Adversaries remove or manipulate network connections using built-in utilities such as `netsh`, `iptables`, `ufw`, or disabling logging mechanisms to avoid detection and response.",
        "hypothesis": [
            "Are there unauthorized modifications to firewall rules or network configurations?",
            "Are adversaries leveraging command-line utilities to manipulate network logs?",
            "Is there an increase in VPN or proxy modifications following malicious activity?"
        ],
        "log_sources": [
            {"type": "Network Traffic Logs", "source": "Firewall Logs, Proxy Logs, IDS/IPS Logs"},
            {"type": "Process Creation Logs", "source": "Sysmon (Event ID 1, 3, 13), Linux Auditd, Windows Security Logs (Event ID 5156, 5025)"},
            {"type": "Endpoint Logs", "source": "EDR (CrowdStrike, Defender ATP, Carbon Black)"},
            {"type": "Security Monitoring Tools", "source": "SIEM, Host-based IDS Logs"}
        ],
        "detection_methods": [
            "Monitor for execution of known network manipulation commands (`netsh advfirewall`, `iptables -F`, `ufw disable`).",
            "Detect unauthorized firewall modifications and network disconnections.",
            "Identify VPN or proxy settings changes that could be used to bypass security monitoring."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search command=*netsh* OR command=*iptables* OR command=*ufw* \n| stats count by host, user, command"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify unauthorized network connection removals.",
            "Analyze Process Creation Logs: Detect anomalies in firewall and network rule modifications.",
            "Monitor for Unauthorized Network Changes: Identify use of `netsh`, `iptables`, or `ufw` commands.",
            "Correlate with Threat Intelligence: Compare with known defense evasion techniques.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Network Manipulation Detected: Block unauthorized network configuration changes and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for network connection removal-based defense evasion techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1070.005 (Network Connection Removal)", "example": "Adversaries using `iptables -F` to remove firewall rules."},
            {"tactic": "Persistence", "technique": "T1547 (Boot or Logon Autostart Execution)", "example": "Malware maintaining persistence while hiding its traces by modifying network connections."}
        ],
        "watchlist": [
            "Flag unexpected executions of network modification commands.",
            "Monitor for anomalies in network rule deletion activities.",
            "Detect unauthorized modifications to VPN, proxy, or firewall settings."
        ],
        "enhancements": [
            "Deploy network configuration monitoring to detect unauthorized changes.",
            "Implement behavioral analytics to detect abnormal network activity.",
            "Improve correlation between network modification activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious network connection removal-based defense evasion activity and affected systems.",
        "remediation": "Block unauthorized network changes, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of network manipulation-based defense evasion techniques."
    }
