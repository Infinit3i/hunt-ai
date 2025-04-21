def get_content():
    return {
        "id": "T1596.001",
        "url_id": "T1596/001",
        "title": "Search Open Technical Databases: DNS/Passive DNS",
        "description": "Adversaries may search DNS data for information about victims that can be used during targeting. DNS records, including those in passive DNS databases, can reveal valuable details like subdomains, mail servers, and infrastructure exposure.",
        "tags": ["dns", "passive dns", "osint", "reconnaissance", "enumeration"],
        "tactic": "Reconnaissance",
        "protocol": "DNS",
        "os": "",
        "tips": [
            "Configure DNS servers to avoid zone transfers and unauthorized lookups.",
            "Use split-horizon DNS to restrict visibility of internal DNS records.",
            "Regularly audit your DNS exposure using tools like DNSDumpster, PassiveTotal, or CIRCL."
        ],
        "data_sources": "Domain Name, Network Traffic, Internet Scan",
        "log_sources": [
            {"type": "Domain Name", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Internet Scan", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Command History", "location": "~/.bash_history", "identify": "Use of dig, nslookup, or dnsenum"},
            {"type": "Browser History", "location": "Adversary Workstation", "identify": "Access to DNS recon services like DNSDumpster or PassiveTotal"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "DNS Resolver/Server", "identify": "Suspicious DNS query patterns to external DNS services"}
        ],
        "detection_methods": [
            "Monitor DNS logs for unusual query volumes or unauthorized AXFR requests.",
            "Review access to passive DNS services from organizational networks.",
            "Correlate external DNS enumeration attempts with reconnaissance behavior."
        ],
        "apt": [],
        "spl_query": [
            'index=dns OR index=proxy\n| search uri_domain IN ("dnsdumpster.com", "passivetotal.org", "securitytrails.com", "crt.sh")\n| stats count by src_ip, uri_domain'
        ],
        "hunt_steps": [
            "Identify domains and subdomains visible in public DNS records.",
            "Correlate any recent suspicious DNS queries to internal infrastructure.",
            "Detect zone transfer attempts (AXFR) in DNS logs."
        ],
        "expected_outcomes": [
            "Map of organization subdomains and potential mail or web infrastructure visible to adversaries.",
            "Improved detection and hardening of DNS services against enumeration."
        ],
        "false_positive": "Legitimate scans from uptime monitoring or internal red teams may mimic DNS enumeration behavior.",
        "clearing_steps": [
            "Disable public zone transfers (AXFR) on authoritative name servers.",
            "Mask or remove sensitive subdomains from public DNS if unnecessary.",
            "Enforce DNS query rate-limiting and anomaly detection."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-dns-exfiltration"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1133", "example": "Enumeration of VPN or RDP endpoints exposed via DNS"},
            {"tactic": "Resource Development", "technique": "T1583", "example": "Registering similar-looking subdomains for phishing based on passive DNS reconnaissance"}
        ],
        "watchlist": [
            "Unusual DNS query patterns from external IPs",
            "Frequent lookups to internal-only domains by non-corporate resolvers",
            "Use of web-based DNS reconnaissance services"
        ],
        "enhancements": [
            "Deploy DNS anomaly detection with machine learning on query patterns.",
            "Integrate threat intelligence feeds with passive DNS to alert on leaked internal names.",
            "Red team exercises focused on DNS enumeration and detection tuning."
        ],
        "summary": "DNS and passive DNS databases provide attackers insight into an organization's infrastructure. DNS misconfigurations and exposed subdomains often precede targeted attacks.",
        "remediation": "Restrict zone transfers, review public DNS exposure, and apply split-horizon DNS where feasible.",
        "improvements": "Integrate DNS monitoring into your SIEM and develop alerts for AXFR attempts, new external subdomain lookups, or repeated recon domain access.",
        "mitre_version": "16.1"
    }
