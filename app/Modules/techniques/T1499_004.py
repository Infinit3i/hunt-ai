def get_content():
    return {
        "id": "T1499.004",
        "url_id": "T1499/004",
        "title": "Endpoint Denial of Service: Application or System Exploitation",
        "description": "Adversaries may exploit software vulnerabilities that cause applications or systems to crash, creating a denial of service condition. These may be re-exploited persistently and can extend to dependent services or systems.",
        "tags": ["dos", "exploit", "crash", "impact", "availability", "zero-day"],
        "tactic": "Impact",
        "protocol": "",
        "os": "IaaS, Linux, Windows, macOS",
        "tips": [
            "Patch critical applications and services regularly.",
            "Use exception handling and service restart logic with alerting.",
            "Monitor for abnormal crash loops or high availability service flapping."
        ],
        "data_sources": "Application Log: Application Log Content, Network Traffic: Network Traffic Content, Network Traffic: Network Traffic Flow, Sensor Health: Host Status",
        "log_sources": [
            {"type": "Application Log", "source": "Crash Logs", "destination": "System Monitor"},
            {"type": "Network Traffic", "source": "Traffic Flow", "destination": "Sensor Health"},
            {"type": "Sensor Health", "source": "Host Status", "destination": "Availability Monitoring"}
        ],
        "source_artifacts": [
            {"type": "Exploit Trigger", "location": "Application Entry Point", "identify": "Malformed request or payload leading to crash"}
        ],
        "destination_artifacts": [
            {"type": "Crash Dump", "location": "System/Application Logs", "identify": "Critical failure signatures or core dumps"}
        ],
        "detection_methods": [
            "Log monitoring for frequent application crash events",
            "Signature-based IDS/IPS rules for known exploitation patterns",
            "Sensor-based health alerting for repeated service restarts"
        ],
        "apt": [
            "Industroyer operators"
        ],
        "spl_query": [
            "index=crash_logs OR index=os_logs \"exception\" OR \"fault\" OR \"core dumped\"\n| stats count by host, process_name, error_type",
            "index=network_logs signature=\"Exploit Attempt\" severity=high\n| stats count by source_ip, target_app"
        ],
        "hunt_steps": [
            "Search for repeated crash logs tied to same service/process.",
            "Check for network payloads matching known CVE exploit signatures.",
            "Correlate app uptime flapping with previous inbound request logs."
        ],
        "expected_outcomes": [
            "Identification of adversarial activity triggering app/system DoS",
            "Insight into exploit-based disruptions and remediation points"
        ],
        "false_positive": "Poorly written applications or unstable third-party integrations may also crash under normal use or user error.",
        "clearing_steps": [
            "Patch known vulnerabilities in the affected software.",
            "Apply WAF or IPS rules to block exploit payloads.",
            "Restore service and enable crash loop protections."
        ],
        "mitre_mapping": [
            {"tactic": "Impact", "technique": "T1489", "example": "Service Stop"},
            {"tactic": "Impact", "technique": "T1495", "example": "Firmware Corruption"},
            {"tactic": "Impact", "technique": "T1485", "example": "Data Destruction"}
        ],
        "watchlist": [
            "High-frequency crashes or unexpected service restarts",
            "External IPs accessing known vulnerable endpoints"
        ],
        "enhancements": [
            "Deploy host-based EDR to monitor and alert on crash loops or kernel panics.",
            "Use container health checks and auto-healing strategies for HA environments."
        ],
        "summary": "Exploitation of software vulnerabilities to crash systems or applications is a powerful method for creating denial-of-service effects. These may be persistent if vulnerabilities remain unpatched.",
        "remediation": "Patch and harden all externally facing and critical infrastructure components. Block known exploit vectors with layered defense.",
        "improvements": "Integrate exploit detection signatures in both host and network layers. Automate alerting and response to crash events and system instability."
    }
