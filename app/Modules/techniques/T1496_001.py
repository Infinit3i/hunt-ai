def get_content():
    return {
        "id": "T1496.001",
        "url_id": "T1496/001",
        "title": "Resource Hijacking: Compute Hijacking",
        "description": "Adversaries may leverage the compute resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability.",
        "tags": ["impact", "compute", "cryptojacking", "mining", "containers", "cloud abuse", "availability"],
        "tactic": "Impact",
        "protocol": "",
        "os": "Windows, Linux, macOS, Containers, IaaS",
        "tips": [
            "Monitor container APIs for unauthorized deployments.",
            "Inspect for abnormal CPU/GPU usage on endpoints and servers.",
            "Alert on known cryptomining processes and binaries.",
            "Use cloud security tools to detect excessive compute usage or scaling anomalies."
        ],
        "data_sources": "Command, File, Network Traffic, Process, Sensor Health",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "File", "source": "File Creation", "destination": ""},
            {"type": "Network Traffic", "source": "Network Connection Creation", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Content", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Flow", "destination": ""},
            {"type": "Process", "source": "Process Creation", "destination": ""},
            {"type": "Sensor Health", "source": "Host Status", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Sysmon Logs", "location": "Sysmon", "identify": "Detection of mining executables like xmrig or kinsing"},
            {"type": "Process List", "location": "Memory", "identify": "Unauthorized processes with high CPU usage"},
            {"type": "Network Connections", "location": "System netstat or EDR logs", "identify": "Connections to mining pool addresses"},
            {"type": "Registry Hives", "location": "HKCU/HKLM", "identify": "Persistence keys linked to miners"},
            {"type": "File Access Times (MACB)", "location": "Filesystem", "identify": "Recently created binaries with mining signatures"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Firewall Logs", "identify": "Outbound traffic to mining pools"},
            {"type": "Sensor Health", "location": "Cloud Monitoring", "identify": "System degradation due to compute overuse"}
        ],
        "detection_methods": [
            "Detect mining tools like xmrig, minerd, kinsing via hashes or command-line arguments.",
            "Monitor for excessive or abnormal compute resource utilization.",
            "Inspect network activity for connections to known cryptomining pools.",
            "Alert on container creation from unapproved sources."
        ],
        "apt": ["APT41", "Rocke", "TeamTNT", "Mockingbird", "Kinsing", "CookieMiner", "DarkGate", "Skidmap"],
        "spl_query": [
            'index=sysmon\n| search process_name="xmrig" OR command_line="*kinsing*"\n| stats count by user, host',
            'index=network_traffic\n| search dest_ip IN ("*pool*", "*crypto*", "*mining*")\n| stats count by src_ip, dest_ip',
            'index=container_logs\n| search image_name IN ("*xmrig*", "*miner*", "*kinsing*")\n| stats count by container_id, host'
        ],
        "hunt_steps": [
            "Scan endpoints and servers for high CPU/GPU load trends.",
            "Inspect container logs and images for unapproved deployments.",
            "Review scheduled tasks or services for auto-launching miners.",
            "Correlate network connections to known mining pool IPs and domains."
        ],
        "expected_outcomes": [
            "Discovery of cryptomining software or scripts on endpoints, servers, or containers.",
            "Identification of affected infrastructure and associated user accounts.",
            "Detection of persistence or lateral movement mechanisms related to cryptominers."
        ],
        "false_positive": "Legitimate high-performance computing workloads may trigger similar CPU or network usage alerts. Confirm process legitimacy and destination domains.",
        "clearing_steps": [
            "Stop miner process: taskkill /F /IM xmrig.exe",
            "Delete malicious files: rm -rf /tmp/kinsing; del C:\\miner\\* /Q",
            "Remove unauthorized container: docker rm -f suspicious_container",
            "Remove persistence: schtasks /Delete /TN \"mining_task\" /F",
            "Revert cloud compute scaling changes to original baseline"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-resource-abuse"],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1053.005", "example": "Scheduled task created to maintain miner execution"},
            {"tactic": "Execution", "technique": "T1059.001", "example": "Miner launched via PowerShell or Bash script"}
        ],
        "watchlist": [
            "Presence of mining processes: xmrig, kinsing, minerd",
            "High CPU/GPU consumption spikes",
            "Outbound traffic to mining pool domains or IPs",
            "Unusual container creation activity"
        ],
        "enhancements": [
            "Deploy container security monitoring agents.",
            "Apply YARA rules across endpoints and containers.",
            "Integrate cloud usage anomaly detection into SIEM workflows."
        ],
        "summary": "Compute Hijacking is a sub-technique of Resource Hijacking in which adversaries exploit compromised systems, often cloud or containerized environments, to perform high-compute operations such as cryptocurrency mining.",
        "remediation": "Kill mining processes, remove dropped binaries, revoke persistence, clean up unauthorized containers, and audit impacted resources.",
        "improvements": "Enforce strong access control for container APIs, baseline system performance, monitor command-line execution paths.",
        "mitre_version": "16.1"
    }
