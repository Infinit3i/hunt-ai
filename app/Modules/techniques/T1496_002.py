def get_content():
    return {
        "id": "T1496.002",
        "url_id": "T1496/002",
        "title": "Resource Hijacking: Bandwidth Hijacking",
        "description": "Adversaries may leverage the network bandwidth resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability.",
        "tags": ["impact", "bandwidth", "proxyjacking", "botnet", "dos", "recon", "availability"],
        "tactic": "Impact",
        "protocol": "",
        "os": "Windows, Linux, macOS, Containers, IaaS",
        "tips": [
            "Monitor for high outbound traffic patterns or scanning activity.",
            "Inspect for proxyware installations and network tunneling tools.",
            "Alert on known botnet-related binaries and command lines.",
            "Set rate limits or traffic thresholds for unexpected outbound flows."
        ],
        "data_sources": "Command, File, Network Traffic, Process",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "File", "source": "File Creation", "destination": ""},
            {"type": "Network Traffic", "source": "Network Connection Creation", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Content", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Flow", "destination": ""},
            {"type": "Process", "source": "Process Creation", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Process List", "location": "System memory or EDR telemetry", "identify": "Proxyware or torrent client processes"},
            {"type": "File Access Times (MACB)", "location": "Filesystem", "identify": "Executable or installer files of proxyjacking tools"},
            {"type": "Network Connections", "location": "Firewall or netstat logs", "identify": "Persistent outbound traffic to proxy service IPs"},
            {"type": "Sysmon Logs", "location": "Sysmon", "identify": "Command-line execution of proxy-related tools"},
            {"type": "Event Logs", "location": "Windows Security", "identify": "Unusual spikes in outbound connection creation events"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Firewall logs", "identify": "Outbound traffic to known proxyjacking services"},
            {"type": "Process List", "location": "Targeted services", "identify": "Participation in DoS activities or mass scanning"}
        ],
        "detection_methods": [
            "Identify high bandwidth usage trends not associated with normal workload.",
            "Detect and block known proxyware installations.",
            "Monitor for network scans and outbound DoS-style traffic.",
            "Look for long-lasting or unusually frequent outbound sessions to unknown IPs."
        ],
        "apt": ["TeamTNT", "GoBotKR", "Rocke"],
        "spl_query": [
            'index=network_traffic\n| stats avg(bytes_out) by src_ip\n| where avg(bytes_out) > 10000000\n| sort -avg(bytes_out)',
            'index=sysmon\n| search process_name="proxyware.exe" OR command_line="*proxyjacking*"\n| stats count by host, user',
            'index=os_logs\n| search command="*masscan*" OR command="*zmap*"\n| stats count by host, user'
        ],
        "hunt_steps": [
            "Identify systems generating excessive outbound traffic.",
            "Review processes communicating with known proxyware or scanning services.",
            "Search for known proxyjacking installers or services.",
            "Cross-reference traffic destinations with known malicious infrastructure."
        ],
        "expected_outcomes": [
            "Detection of systems engaged in bandwidth resale or DoS attacks.",
            "Attribution of bandwidth abuse to specific processes or user accounts.",
            "Visibility into lateral movement or additional compromised nodes."
        ],
        "false_positive": "Legitimate CDN, backup services, or file transfers may generate high outbound traffic. Validate the process, user, and destination before escalating.",
        "clearing_steps": [
            "Terminate proxyjacking process: taskkill /F /IM proxyware.exe",
            "Remove dropped binaries: del C:\\Users\\Public\\proxyjacking\\* /Q",
            "Inspect scheduled tasks or startup scripts for persistence: schtasks /Query | findstr proxy",
            "Block known proxyjacking domains/IPs in firewall",
            "Reset system network configuration to defaults"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-resource-abuse"],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1046", "example": "Mass scanning to find more exploitable endpoints"},
            {"tactic": "Command and Control", "technique": "T1090.003", "example": "Proxy communication through external services"}
        ],
        "watchlist": [
            "Unusual spike in outbound traffic per host",
            "Processes associated with zmap, masscan, or proxy clients",
            "New firewall rules allowing persistent outbound connections",
            "Domains/IPs linked to proxyjacking services"
        ],
        "enhancements": [
            "Use rate-limiting and QoS controls to restrict excessive bandwidth use.",
            "Integrate NetFlow data into SIEM for cross-host correlation.",
            "Deploy EDR detections for common proxyjacking binaries and behaviors."
        ],
        "summary": "Bandwidth Hijacking involves adversaries abusing network resources of compromised systems for illicit purposes such as proxyjacking, DoS attacks, or malicious scanning. This can lead to service degradation, financial loss, or reputational harm.",
        "remediation": "Identify and stop bandwidth-heavy unauthorized processes, remove proxyware, reset persistence, and monitor for recurrence.",
        "improvements": "Enhance network traffic monitoring, deploy behavioral detections for proxyware, and apply strict outbound traffic filtering.",
        "mitre_version": "16.1"
    }
