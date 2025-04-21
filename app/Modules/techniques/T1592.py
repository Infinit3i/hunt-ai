def get_content():
    return {
        "id": "T1592",
        "url_id": "T1592",
        "title": "Gather Victim Host Information",
        "description": "Adversaries may gather information about the victim's hosts that can be used during targeting. This can include administrative data like IP addresses or hostnames, and configuration details such as operating system or language.",
        "tags": ["reconnaissance", "host intelligence", "victim profiling"],
        "tactic": "Reconnaissance",
        "protocol": "HTTP",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Monitor for suspicious user-agent patterns in HTTP requests.",
            "Use threat intelligence to correlate scanning IPs with known APT infrastructure."
        ],
        "data_sources": "Internet Scan",
        "log_sources": [
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "Windows Security", "source": "", "destination": ""},
            {"type": "Sysmon", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "UserAssist", "location": "Registry - NTUSER.DAT", "identify": "Access to reconnaissance-linked pages"},
            {"type": "DNS Cache", "location": "System Memory", "identify": "Resolution of suspicious reconnaissance domains"}
        ],
        "destination_artifacts": [
            {"type": "Event Logs", "location": "%SystemRoot%\\System32\\winevt\\Logs", "identify": "Banner grabbing or probe indicators"}
        ],
        "detection_methods": [
            "Detect anomalies in user-agent HTTP headers",
            "Monitor passive DNS traffic for resolution of reconnaissance-related domains",
            "Log analysis for patterns consistent with host probing"
        ],
        "apt": [
            "Qakbot", "APT41"
        ],
        "spl_query": [
            "index=web_logs user_agent=*Linux* OR user_agent=*Windows NT* OR user_agent=*Darwin*\n| stats count by src_ip, user_agent"
        ],
        "hunt_steps": [
            "Check firewall logs for repetitive queries from single IPs",
            "Analyze endpoint telemetry for probing patterns",
            "Inspect proxy logs for excessive user-agent variation"
        ],
        "expected_outcomes": [
            "Detection of hosts sending reconnaissance-related traffic",
            "Insight into early phases of adversary campaign planning"
        ],
        "false_positive": "Web crawlers or legitimate scanners may produce similar traffic patterns.",
        "clearing_steps": [
            "Clear DNS cache: ipconfig /flushdns",
            "Reset browser configuration and user-agent: registry edits or GPO",
            "Delete browsing and user activity logs"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "T1587", "example": "Develop targeting tools after host info enumeration"},
            {"tactic": "Initial Access", "technique": "T1133", "example": "Exploit remote services based on gathered host data"}
        ],
        "watchlist": [
            "User agents requesting only OS-specific malware",
            "Unexpected banner-grabbing signatures from endpoints"
        ],
        "enhancements": [
            "Deploy deception pages to mislead user-agent collection",
            "Integrate endpoint agent with user-agent logging modules"
        ],
        "summary": "Adversaries seek host-specific intelligence like OS and hostname data to plan further actions, often via web beacons or scans.",
        "remediation": "Tighten web server headers, sanitize user-agent exposure, and regularly rotate asset naming schemes.",
        "improvements": "Enrich user-agent parsing analytics, validate DNS logs against threat feeds, and detect fingerprinting frameworks.",
        "mitre_version": "16.1"
    }