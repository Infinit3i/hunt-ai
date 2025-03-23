def get_content():
    return {
        "id": "T1499",
        "url_id": "T1499",
        "title": "Endpoint Denial of Service",
        "description": "Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users by exhausting system resources or exploiting crash conditions.",
        "tags": ["dos", "ddos", "impact", "endpoint", "resource exhaustion", "botnet"],
        "tactic": "Impact",
        "protocol": "",
        "os": "Containers, IaaS, Linux, Windows, macOS",
        "tips": [
            "Monitor web server logs, application logs, and database logs for spikes or crash loops.",
            "Set threshold alerts for high CPU, memory, or connection counts on endpoints.",
            "Use behavioral baselines to detect abnormal endpoint activity leading to service disruption."
        ],
        "data_sources": "Application Log: Application Log Content, Network Traffic: Network Traffic Content, Network Traffic: Network Traffic Flow, Sensor Health: Host Status",
        "log_sources": [
            {"type": "Application Log", "source": "Web/Application Server", "destination": "System Monitoring"},
            {"type": "Network Traffic", "source": "Traffic Flow", "destination": "Sensor Health"},
            {"type": "Sensor Health", "source": "Host Status", "destination": "Monitoring System"}
        ],
        "source_artifacts": [
            {"type": "Malicious Requests", "location": "Botnet Systems", "identify": "High volume or malformed endpoint hits"}
        ],
        "destination_artifacts": [
            {"type": "Crash Logs", "location": "System or Service Logs", "identify": "Repeated failure events or service restarts"}
        ],
        "detection_methods": [
            "Network throughput monitoring with NetFlow/SNMP",
            "Real-time system metrics alerting (CPU, memory, process spikes)",
            "Analysis of error logs and HTTP status codes (e.g., 500, 503)"
        ],
        "apt": [
            "APT41", "Dukes", "ZxShell operators", "GRU Unit 74455"
        ],
        "spl_query": [
            "index=infra_logs sourcetype=web_server_logs status_code=503 OR status_code=500\n| stats count by uri, client_ip",
            "index=os_logs sourcetype=host_metrics cpu_usage>95 memory_usage>90\n| timechart span=1m avg(cpu_usage) avg(memory_usage)"
        ],
        "hunt_steps": [
            "Review high CPU/memory events across systems under DoS.",
            "Identify IPs with sustained POST/GET request floods in short durations.",
            "Cross-reference crashes with correlated network anomalies."
        ],
        "expected_outcomes": [
            "Detection of resource exhaustion from malicious clients",
            "Early alerting of crash loops or degraded system behavior"
        ],
        "false_positive": "Legitimate load-testing or peak usage periods may cause similar signs; contextual validation is essential.",
        "clearing_steps": [
            "Block offending IPs via firewall or WAF.",
            "Scale up affected services and apply load balancing or rate limiting.",
            "Patch or harden services against known DoS exploits."
        ],
        "mitre_mapping": [
            {"tactic": "Impact", "technique": "T1498", "example": "Network Denial of Service"},
            {"tactic": "Impact", "technique": "T1565.001", "example": "Data Manipulation: Stored Data"}
        ],
        "watchlist": [
            "Unusual request rates per client IP",
            "Repeated system restarts or crash dumps"
        ],
        "enhancements": [
            "Enable automated scaling and traffic throttling for web services.",
            "Use behavioral anomaly detection for service availability monitoring."
        ],
        "summary": "Endpoint Denial of Service disrupts availability by exhausting system resources or causing crashes at various layers of the application stack. This can be achieved with or without high traffic volume and is distinct from traditional network flooding attacks.",
        "remediation": "Apply resource limits, DDoS protections, and increase service resiliency through rate-limiting and horizontal scaling.",
        "improvements": "Enhance observability of system metrics and integrate service health telemetry with detection logic to reduce mean-time-to-recovery during endpoint DoS events."
    }
