def get_content():
    return {
        "id": "T1499.003",
        "url_id": "T1499/003",
        "title": "Endpoint Denial of Service: Application Exhaustion Flood",
        "description": "Adversaries may target resource-intensive features of applications to cause a denial of service (DoS), overwhelming the system and denying legitimate access.",
        "tags": ["dos", "application flood", "impact", "resource exhaustion", "endpoint"],
        "tactic": "Impact",
        "protocol": "HTTP, HTTPS, API Calls",
        "os": "IaaS, Linux, Windows, macOS",
        "tips": [
            "Monitor for abnormal spikes in API or resource-heavy endpoint calls.",
            "Analyze request patterns that hit the same application function repeatedly.",
            "Deploy rate-limiting or CAPTCHA protection for sensitive web features."
        ],
        "data_sources": "Application Log: Application Log Content, Network Traffic: Network Traffic Content, Network Traffic: Network Traffic Flow, Sensor Health: Host Status",
        "log_sources": [
            {"type": "Application Log", "source": "Web/Application Server", "destination": "System Monitoring"},
            {"type": "Network Traffic", "source": "Traffic Flow", "destination": "Sensor Health"},
            {"type": "Sensor Health", "source": "Host Status", "destination": "Monitoring System"}
        ],
        "source_artifacts": [
            {"type": "Flood Request", "location": "Web/App Feature", "identify": "Multiple identical or intensive requests to one endpoint"}
        ],
        "destination_artifacts": [
            {"type": "Service Degradation Logs", "location": "Web/Application Logs", "identify": "Errors like 500, 503 or out-of-resource exceptions"}
        ],
        "detection_methods": [
            "Rate analysis per endpoint/function",
            "Log inspection for repeated access patterns or errors",
            "CPU and memory monitoring for app-specific spikes"
        ],
        "apt": [],
        "spl_query": [
            "index=weblogs uri=\"/api/heavy_endpoint\"\n| stats count by client_ip\n| where count > 1000",
            "index=app_logs status_code=500 OR status_code=503\n| stats count by uri, client_ip"
        ],
        "hunt_steps": [
            "Identify endpoints with abnormally high request rates.",
            "Check logs for functions with increased execution time or repeated error states.",
            "Match IPs across logs that continuously hit resource-intensive paths."
        ],
        "expected_outcomes": [
            "Early detection of abuse to web app functions",
            "System alerts for resource exhaustion via high-volume legitimate requests"
        ],
        "false_positive": "High user activity during sales, marketing, or launch events can appear similar to a DoS pattern.",
        "clearing_steps": [
            "Apply rate-limiting to the abused function.",
            "Deploy caching and optimize app logic for heavy functions.",
            "Blacklist abusive IPs or apply CAPTCHA mechanisms."
        ],
        "mitre_mapping": [
            {"tactic": "Impact", "technique": "T1498", "example": "Application Layer Protocol Flood"}
        ],
        "watchlist": [
            "Endpoints receiving > X requests per second",
            "Logs showing repetitive error codes from same client"
        ],
        "enhancements": [
            "Introduce auto-scaling for affected services",
            "Leverage WAF to detect and throttle suspicious requests"
        ],
        "summary": "Application Exhaustion Flood attacks focus on overwhelming specific high-load functionalities in apps, bypassing traditional network-layer DoS protections to bring down backend services.",
        "remediation": "Implement application-layer defenses such as input throttling, dynamic rate limiting, and error monitoring for early warnings.",
        "improvements": "Enhance observability into function-specific traffic and align DevOps/IR teams on feature protection strategies during critical release windows."
    }
