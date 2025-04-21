def get_content():
    return {
        "id": "T1665",
        "url_id": "T1665",
        "title": "Hide Infrastructure",
        "description": "Adversaries may manipulate network traffic or infrastructure metadata to hide and evade detection of their command and control (C2) infrastructure. Techniques include traffic filtering to avoid scanning and analysis, the use of proxies, VPNs, and TOR to mask the origin of C2, and domain name obfuscation using trusted services, misleading names, or redirection logic. Infrastructure may also be hosted on compromised systems or reputable cloud providers to blend in with normal traffic. Additional evasion may involve blocking known researcher IPs, using schema-abuse techniques, or delaying malicious redirection until certain environmental conditions are met.",
        "tags": ["c2", "defense evasion", "domain hiding", "network obfuscation", "VPN", "proxy", "tor", "schema abuse"],
        "tactic": "Command and Control",
        "protocol": "Various",
        "os": "Linux, Network, Windows, macOS",
        "tips": [
            "Monitor new domain registrations resembling known brands or infrastructure",
            "Correlate VPN/proxy IPs against known provider lists",
            "Look for fast-flux DNS or unusual TTL patterns in DNS resolution"
        ],
        "data_sources": "Domain Name: Domain Registration, Internet Scan: Response Content, Internet Scan: Response Metadata, Network Traffic: Network Traffic Content",
        "log_sources": [
            {"type": "Domain Name", "source": "WHOIS, Passive DNS, OSINT", "destination": ""},
            {"type": "Internet Scan", "source": "Shodan, Censys, GreyNoise", "destination": ""},
            {"type": "Network Traffic", "source": "Zeek, Suricata, Firewall Logs", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Domain Registration", "location": "WHOIS, registrar API", "identify": "suspicious domains mimicking real brands"},
            {"type": "Proxy Usage", "location": "VPN endpoint IP pools", "identify": "connections to commercial VPN providers"},
            {"type": "URL Redirection", "location": "HTTP headers and meta refresh", "identify": "malicious domains redirecting conditionally"}
        ],
        "destination_artifacts": [
            {"type": "C2 Infrastructure", "location": "Cloud-hosted services or compromised assets", "identify": "hidden endpoints"},
            {"type": "Blocked IP Bypass", "location": "Firewall logs", "identify": "use of anonymizers to bypass IP-based controls"}
        ],
        "detection_methods": [
            "Track newly registered domains and compare against threat intel watchlists",
            "Detect obfuscation using schema-abuse patterns (e.g., misleading subdomains)",
            "Analyze VPN/proxy/tor traffic for behavioral anomalies",
            "Use open-source scanners (Shodan, Censys) to identify exposed services"
        ],
        "apt": [],
        "spl_query": "index=network sourcetype=firewall_logs \n| search dest_ip=*vpn* OR dest_ip=*proxy* OR dest_ip=*tor* \n| stats count by dest_ip",
        "spl_rule": "https://research.splunk.com/detections/tactics/command-and-control/",
        "elastic_rule": "https://grep.app/search?f.repo=elastic%2Fdetection-rules&q=T1665",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1665",
        "hunt_steps": [
            "Perform WHOIS and Passive DNS lookups for newly registered infrastructure",
            "Check open-source scan data for hidden or previously unknown C2 endpoints",
            "Monitor redirection chains and conditional logic in HTTP responses",
            "Compare VPN/proxy IPs against known threat actor infrastructure",
            "Cross-reference domains with threat intelligence feeds"
        ],
        "expected_outcomes": [
            "Detection of adversary infrastructure using anonymization services",
            "Identification of malicious or misleading domain registrations",
            "Blocked access to C2 through detection of proxy-evaded traffic"
        ],
        "false_positive": "Legitimate services and researchers may use VPNs or proxies. Carefully correlate with destination domains and behavioral context.",
        "clearing_steps": [
            "Block identified malicious IPs and domains at firewall, proxy, or DNS layers",
            "Report malicious infrastructure to domain registrars and hosting providers",
            "Update detection signatures for evasion techniques such as schema abuse"
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1665", "example": "Use of residential proxies or bulletproof hosting to mask C2"}
        ],
        "watchlist": [
            "Monitor VPN and proxy traffic anomalies",
            "Flag new domains that mimic legitimate services",
            "Track redirection patterns hiding final destination"
        ],
        "enhancements": [
            "Deploy passive DNS monitoring with TTL anomaly detection",
            "Incorporate Greynoise and Shodan into automated enrichment pipelines",
            "Use cloud-based sandboxing to identify delayed redirection to C2"
        ],
        "summary": "Adversaries hide the origin of their infrastructure using proxies, domain name tricks, traffic filtering, and redirection logic. Monitoring domain creation, open service scans, and anomalous traffic patterns is critical to uncovering and disrupting these techniques.",
        "remediation": "Block discovered C2 infrastructure, redirect domains to sinkholes, and alert upstream providers when applicable. Track adversary evasion methods and rotate blocklists regularly.",
        "improvements": "Develop heuristics for schema abuse and dynamic redirect tracking. Combine passive DNS with threat intel correlation for faster detection of hidden infrastructure.",
        "mitre_version": "16.1"
    }
