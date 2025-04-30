def get_content():
    return {
        "id": "T1016.001",
        "url_id": "T1016/001",
        "title": "System Network Configuration Discovery: Internet Connection Discovery",
        "description": "Adversaries may check for Internet connectivity on a system using commands such as ping or tracert to determine if outbound communication is possible.",
        "tags": ["network discovery", "internet check", "ping", "tracert", "outbound test", "connectivity test"],
        "tactic": "Discovery",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor for processes initiating ping or web requests without user interaction.",
            "Set alerts for outbound ICMP from non-standard user accounts.",
            "Investigate tools like curl, wget, or certutil used in odd contexts."
        ],
        "data_sources": "Sysmon, Command, Process",
        "log_sources": [
            {"type": "Sysmon", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Command History", "location": "~/.bash_history", "identify": "Contains ping or tracert usage"},
            {"type": "Sysmon", "location": "Event ID 1", "identify": "Process Create with 'ping', 'curl', or 'tracert'"},
            {"type": "PowerShell", "location": "Event ID 4104", "identify": "Script using Test-NetConnection or Invoke-WebRequest"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Firewall Logs", "identify": "Outbound ICMP or HTTP/HTTPS to known test domains"},
            {"type": "Process List", "location": "Task Manager or ps", "identify": "Running curl, wget, ping"},
            {"type": "DNS Cache", "location": "ipconfig /displaydns", "identify": "Lookups to common test domains like www.google.com"}
        ],
        "detection_methods": [
            "Detect ping, tracert, curl, or wget usage from suspicious parent processes",
            "Alert on outbound connections to popular public test sites (e.g., 8.8.8.8, google.com, baidu.com)",
            "Monitor network traffic for ICMP echo requests or unexpected HTTP GETs"
        ],
        "apt": ["Iron Tiger", "WoodyRAT", "Wocao", "APT29", "ComRAT", "QakBot", "DarkTortilla", "NICKEL", "Actinium", "HAFNIUM", "NOBELIUM", "Layover", "Phosphorus", "UNC3890", "Shuckworm", "Sharpshooter", "Sardonic", "Lyceum", "FIN13"],
        "spl_query": [
            'index=sysmon EventCode=1 \n| search CommandLine="*ping*" OR CommandLine="*tracert*" OR CommandLine="*curl*" OR CommandLine="*wget*"',
            'index=network_traffic \n| search dest_ip=8.8.8.8 OR dest_domain="*.google.com" OR dest_domain="*.microsoft.com"',
            'index=powershell EventCode=4104 \n| search ScriptBlockText="*Test-NetConnection*" OR ScriptBlockText="*Invoke-WebRequest*"'
        ],
        "hunt_steps": [
            "Review logs for recent connectivity tests from endpoints shortly after initial access",
            "Correlate network artifacts with suspicious process launches",
            "Identify use of connectivity tools by abnormal users or via remote sessions"
        ],
        "expected_outcomes": [
            "Outbound connectivity validation by threat actor tools",
            "Artifacts showing ping or HTTP traffic to public or attacker infrastructure",
            "Confirmation of internet availability from compromised system"
        ],
        "false_positive": "Legitimate users and IT administrators may run ping or network tests as part of routine troubleshooting.",
        "clearing_steps": [
            "Clear command history files or PowerShell history",
            "Delete scripts or batch files used to run tests",
            "Flush DNS cache and clear browser history"
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1071.001", "example": "After validating internet access, adversary establishes C2 over HTTP(S)"},
            {"tactic": "Defense Evasion", "technique": "T1562.004", "example": "Connection checks help evade detection by avoiding blocked proxies"}
        ],
        "watchlist": [
            "ICMP Echo Requests originating from uncommon sources",
            "GET/POST requests to IPs or domains not typically accessed",
            "Outbound connectivity tools used from non-CLI processes"
        ],
        "enhancements": [
            "Enable Sysmon ProcessCreate and PowerShell ScriptBlock logging",
            "Correlate DNS queries with command execution",
            "Tag popular connectivity check domains (e.g., google.com) in proxy logs"
        ],
        "summary": "Internet Connection Discovery is used by adversaries to determine if the compromised host has internet access to initiate command-and-control or further actions.",
        "remediation": "Limit access to outbound connections from sensitive systems. Enforce proxy inspection and restrict tools capable of connectivity checks.",
        "improvements": "Use endpoint behavior analytics to baseline and alert on connectivity commands. Correlate command execution with network activity to highlight suspicious usage.",
        "mitre_version": "16.1"
    }
