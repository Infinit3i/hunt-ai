def get_content():
    return {
        "id": "T1496",
        "url_id": "T1496",
        "title": "Resource Hijacking",
        "description": "Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability.",
        "tags": ["impact", "resource usage", "cryptojacking", "proxyjacking", "cloud abuse", "availability"],
        "tactic": "Impact",
        "protocol": "",
        "os": "Windows, Linux, macOS, SaaS, IaaS, Containers",
        "tips": [
            "Monitor for excessive CPU/GPU usage and unusual process behavior.",
            "Establish baselines for system performance and alert on anomalies.",
            "Review cloud service usage for spikes or suspicious billing activity.",
            "Use endpoint and network-based detection for known mining tools."
        ],
        "data_sources": "Application Log, Cloud Service, Command, File, Network Traffic, Process, Sensor Health",
        "log_sources": [
            {"type": "Application Log", "source": "Application Log Content", "destination": ""},
            {"type": "Cloud Service", "source": "Cloud Service Modification", "destination": ""},
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "File", "source": "File Creation", "destination": ""},
            {"type": "Network Traffic", "source": "Network Connection Creation", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Content", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Flow", "destination": ""},
            {"type": "Process", "source": "Process Creation", "destination": ""},
            {"type": "Sensor Health", "source": "Host Status", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Process List", "location": "Memory", "identify": "Suspicious cryptomining processes like xmrig, lolminer, etc."},
            {"type": "File Access Times (MACB Timestamps)", "location": "Filesystem", "identify": "Recent drops or execution of mining tools"},
            {"type": "Sysmon Logs", "location": "Sysmon", "identify": "Unusual process chains or CPU-intensive processes"},
            {"type": "Network Connections", "location": "netstat or equivalent", "identify": "Connections to mining pools or proxy services"},
            {"type": "Windows Defender Logs", "location": "Defender", "identify": "Blocked or flagged cryptomining tools"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Outbound Connections", "identify": "Connection to external mining pools or proxy services"},
            {"type": "Sensor Health", "location": "Cloud monitoring dashboards", "identify": "Degradation in host resource performance"}
        ],
        "detection_methods": [
            "Detect high resource consumption processes.",
            "Identify known cryptominer file hashes or binary signatures.",
            "Monitor unusual network traffic to mining pools or proxy networks.",
            "Track cloud billing or service utilization anomalies."
        ],
        "apt": ["TeamTNT", "Rocke", "8220 Gang"],
        "spl_query": [
            'index=sysmon\n| stats avg(cpu_usage), avg(memory_usage) by process_name\n| where cpu_usage > 80 AND memory_usage > 70\n| sort -cpu_usage',
            'index=network_traffic\n| search dest_ip IN ("*miningpool*", "*cryptonight*", "*monero*")\n| stats count by src_ip, dest_ip',
            'index=os_logs source="powershell"\n| search command IN ("*xmrig*", "*cryptonight*", "*minerd*")\n| stats count by user, host'
        ],
        "hunt_steps": [
            "Review systems with high CPU/memory usage for unauthorized mining tools.",
            "Check for suspicious new services or scheduled tasks.",
            "Inspect outbound connections to known mining pools or proxy services.",
            "Correlate resource usage with known threat actor IOCs."
        ],
        "expected_outcomes": [
            "Identification of unauthorized cryptomining or bandwidth resale activity.",
            "Mapping of affected systems and users.",
            "Detection of persistent mechanisms used to maintain hijacking."
        ],
        "false_positive": "High resource usage from legitimate software such as security scanners, updates, or data processing applications may be mistaken for hijacking. Validate process lineage and destination connections.",
        "clearing_steps": [
            "taskkill /F /IM xmrig.exe",
            "Remove mining tools: del C:\\Users\\Public\\xmrig\\* /Q",
            "Delete persistence mechanisms like scheduled tasks or services",
            "Clear firewall rules added by the attacker: netsh advfirewall firewall delete rule name=\"CryptoMiner\"",
            "Reboot affected systems after clearing artifacts"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-resource-abuse"],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1053.005", "example": "Scheduled Task added to reinitiate miner on reboot"},
            {"tactic": "Command and Control", "technique": "T1071.001", "example": "Miner communicating with mining pool over HTTP/S"}
        ],
        "watchlist": [
            "Frequent connections to mining pools",
            "Sudden spikes in system resource metrics",
            "Unexpected cloud billing increases",
            "Known mining tool executables: xmrig, cpuminer, lolminer"
        ],
        "enhancements": [
            "Enable endpoint detection tools to flag abnormal CPU usage.",
            "Deploy YARA rules to detect common mining tool patterns.",
            "Automate alert triage using thresholds for compute/network usage."
        ],
        "summary": "Resource Hijacking occurs when adversaries co-opt system resources for unauthorized use such as cryptomining, bandwidth resale, or spam generation, resulting in degraded system performance and potential financial cost.",
        "remediation": "Terminate unauthorized processes, remove dropped binaries, revoke persistence mechanisms, investigate external connections, and restore system to secure state.",
        "improvements": "Integrate with cloud cost anomaly detection, automate process profiling, and monitor for lateral movement associated with resource abuse.",
        "mitre_version": "16.1"
    }
