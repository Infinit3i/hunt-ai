def get_content():
    return {
        "id": "T1567",
        "url_id": "1567",
        "title": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "data_sources": "Network Traffic, Web Proxy Logs, Endpoint Logs",
        "protocol": "HTTP, HTTPS, API Requests",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries exfiltrate data using web services to blend with normal traffic and evade detection.",
        "scope": "Monitor web traffic for unusual or unauthorized data transfers.",
        "threat_model": "Adversaries may upload stolen data to cloud storage, file-sharing services, or web APIs to avoid detection by traditional security controls.",
        "hypothesis": [
            "Are there large volumes of outbound HTTP/HTTPS traffic to cloud storage services?",
            "Are users accessing uncommon or unauthorized web services?"
        ],
        "tips": [
            "Monitor for excessive data uploads to file-sharing websites.",
            "Analyze API request patterns for anomalies.",
            "Check endpoint logs for automated scripts interacting with web services."
        ],
        "log_sources": [
            {"type": "Network", "source": "Proxy Logs", "destination": "SIEM"},
            {"type": "Endpoint", "source": "Windows Event Logs", "destination": "Endpoint Security Platform"}
        ],
        "source_artifacts": [
            {"type": "Process Execution", "location": "Sysmon Event ID 1", "identify": "Suspicious command-line web uploads"},
            {"type": "Network Connection", "location": "Firewall Logs", "identify": "Unusual outbound connections"}
        ],
        "destination_artifacts": [
            {"type": "Web Traffic", "location": "Proxy Logs", "identify": "Uploads to cloud storage or unknown domains"}
        ],
        "detection_methods": [
            "Monitor network traffic for large data uploads to external web services.",
            "Detect unusual API requests made by unauthorized users or applications.",
            "Identify scripts or automated tools interacting with file-sharing platforms."
        ],
        "spl_query": [
            "index=web_logs sourcetype=proxy_logs uri_path=*upload* | stats count by src_ip dest_domain"
        ],
        "hunt_steps": [
            "Identify endpoints with abnormal outbound web traffic patterns.",
            "Analyze proxy logs for unauthorized file uploads.",
            "Investigate automated scripts executing frequent API calls."
        ],
        "expected_outcomes": [
            "Detection of unauthorized data exfiltration via web services.",
            "Identification of compromised endpoints utilizing web APIs for exfiltration."
        ],
        "false_positive": "Legitimate business applications may upload files to web services; baseline normal behavior to minimize false positives.",
        "clearing_steps": [
            "Block unauthorized access to cloud storage and file-sharing services.",
            "Enforce strict firewall and proxy rules to prevent unauthorized uploads.",
            "Investigate and terminate malicious processes using web APIs for exfiltration."
        ],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1567", "example": "Data exfiltrated via cloud storage API"}
        ],
        "watchlist": [
            "Excessive or abnormal web uploads from corporate endpoints.",
            "Connections to uncommon or unauthorized web services."
        ],
        "enhancements": [
            "Implement stricter DLP (Data Loss Prevention) policies for web traffic.",
            "Increase logging and monitoring for web API interactions."
        ],
        "summary": "Adversaries may use web services such as cloud storage, social media, or file-sharing platforms to exfiltrate data, avoiding detection by traditional security controls.",
        "remediation": "Restrict and monitor web uploads, enforce strict proxy and firewall rules, and implement behavioral analytics for web traffic.",
        "improvements": "Enhance visibility into outbound web traffic and deploy machine learning models to detect anomalous behavior."
    }
