def get_content():
    """
    Returns structured content for the Web Protocols for C2 technique.
    """
    return {
        "id": "T1071.001",
        "url_id": "T1071/001",
        "title": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "data_sources": "Network Traffic, Proxy Logs, DNS Records, Process Monitoring",
        "protocol": "HTTP, HTTPS",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries use standard web protocols (HTTP/S) for command and control to blend in with legitimate traffic.",
        "scope": "Monitor network and endpoint activity for abnormal web protocol usage.",
        "threat_model": "Attackers leverage web-based communication to evade detection and maintain persistence.",
        "hypothesis": [
            "Are unexpected web requests being made to known C2 domains?",
            "Are there long-lived HTTPS sessions with rare domains?",
            "Is there encrypted traffic to destinations that do not normally support encryption?"
        ],
        "tips": [
            "Analyze unusual or suspicious domain requests in proxy logs.",
            "Monitor for abnormal user-agent strings or headers in HTTP/S traffic.",
            "Detect persistent or periodic web beaconing traffic."
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "Firewall, Proxy Logs", "destination": "SIEM"},
            {"type": "Process Monitoring", "source": "Endpoint Logs", "destination": "Security Analytics"},
            {"type": "DNS Records", "source": "DNS Logs", "destination": "Threat Intelligence"}
        ],
        "source_artifacts": [
            {"type": "Process Execution", "location": "C:\\Windows\\System32", "identify": "Powershell, Curl, Wscript"}
        ],
        "destination_artifacts": [
            {"type": "Network Traffic", "location": "Network Perimeter", "identify": "Anomalous HTTP POST requests"}
        ],
        "detection_methods": [
            "Monitor DNS queries for domains associated with C2 infrastructure.",
            "Detect unusual HTTP request patterns, such as encrypted payloads or frequent small POST requests.",
            "Analyze user-agent strings for anomalies.",
            "Identify processes generating unexpected outbound web traffic."
        ],
        "apt": ["G0007", "G0045"],
        "spl_query": [
            "index=network http_method=POST | stats count by src_ip, dest_ip, user_agent",
            "index=proxy dest_host!=known_domains | table _time, src_ip, dest_host, uri"
        ],
        "hunt_steps": [
            "Review outbound web traffic logs for anomalies.",
            "Correlate network traffic with endpoint process execution.",
            "Investigate domains communicating with endpoints exhibiting suspicious behavior."
        ],
        "expected_outcomes": [
            "Detection of adversary-controlled web C2 infrastructure.",
            "Identification of infected endpoints communicating with malicious domains."
        ],
        "false_positive": "Some web services may use similar patterns for legitimate applications.",
        "clearing_steps": [
            "Block malicious domains via firewall and proxy configurations.",
            "Terminate identified malicious processes on compromised hosts.",
            "Apply threat intelligence feeds to network monitoring solutions."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1071 (Application Layer Protocol)", "example": "Adversaries use HTTP requests to maintain communication with C2 servers."}
        ],
        "watchlist": [
            "Monitor for excessive outbound HTTP/S traffic from a single host.",
            "Identify long-lived web sessions to rare or unknown domains."
        ],
        "enhancements": [
            "Enable deep packet inspection (DPI) on network traffic.",
            "Apply AI-based anomaly detection to identify web-based C2 activity."
        ],
        "summary": "Adversaries use web-based communication to disguise command and control activities within normal traffic.",
        "remediation": "Block and alert on suspicious HTTP/S communications, and investigate affected endpoints.",
        "improvements": "Enhance network telemetry collection and implement stricter domain whitelisting policies."
    }
