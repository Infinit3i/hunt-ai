def get_content():
    return {
        "id": "T1596",
        "url_id": "T1596",
        "title": "Search Open Technical Databases",
        "description": "Adversaries may search freely available technical databases for information about victims that can be used during targeting. These databases include domain registrations, certificate transparency logs, DNS records, passive DNS, CDN configurations, and scan artifacts.",
        "tags": ["reconnaissance", "osint", "open-source-data", "internet-scanning", "network-metadata"],
        "tactic": "Reconnaissance",
        "protocol": "",
        "os": "",
        "tips": [
            "Regularly review your organization's exposure in public data sources such as Shodan, Censys, and crt.sh.",
            "Use DNS split-horizon techniques to separate internal and external records.",
            "Ensure sensitive internal resources are not discoverable through public misconfigurations."
        ],
        "data_sources": "Internet Scan, Certificate, Domain Name, Network Traffic, Asset",
        "log_sources": [
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "Certificate", "source": "", "destination": ""},
            {"type": "Domain Name", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Asset", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Command History", "location": "~/.bash_history", "identify": "Use of recon tools like Shodan CLI, dig, whois"},
            {"type": "Browser History", "location": "Adversary workstation", "identify": "Visits to crt.sh, DNSDumpster, Censys, etc."}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Public Services", "identify": "Connections to scan databases like Shodan or Certificate Transparency logs"}
        ],
        "detection_methods": [
            "Monitor for outgoing queries to passive DNS or scanning platforms.",
            "Use DLP and threat intel to watch for exfiltration or fingerprinting behavior targeting external enumeration sites.",
            "Identify lookups or downloads of crt.sh, Shodan results, or passive DNS logs."
        ],
        "apt": [],
        "spl_query": [
            'index=proxy OR index=dns\n| search uri_domain IN ("shodan.io", "crt.sh", "censys.io", "securitytrails.com", "dnsdumpster.com")\n| stats count by src_ip, uri_domain'
        ],
        "hunt_steps": [
            "Enumerate external-facing services visible in Shodan or Censys.",
            "Search public certificate transparency logs for domain aliases or misissued certs.",
            "Compare public DNS and WHOIS data with internal assets to identify information leakage."
        ],
        "expected_outcomes": [
            "Identification of infrastructure exposed via open technical databases.",
            "Detection of adversary reconnaissance using passive data channels."
        ],
        "false_positive": "Legitimate employee research or red team activity may generate similar queries.",
        "clearing_steps": [
            "Remove or restrict publicly available sensitive infrastructure information.",
            "Limit unnecessary exposure in certificate registration and DNS metadata.",
            "Correct CDN or web hosting misconfigurations."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-data-exfiltration"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1133", "example": "External RDP endpoints discovered via Shodan"},
            {"tactic": "Resource Development", "technique": "T1583", "example": "Using DNS enumeration from public sources to register lookalike domains"}
        ],
        "watchlist": [
            "Unusual spikes in DNS lookups or certificate registrations",
            "Frequent access to known OSINT and scanning platforms",
            "Discovery of internal hostnames or subdomains in crt.sh or VirusTotal"
        ],
        "enhancements": [
            "Deploy threat intelligence correlation between asset inventory and open-source reconnaissance datasets.",
            "Use certificate monitoring to alert on unauthorized or unexpected domain use.",
            "Apply domain and asset tagging for visibility into publicly exposed infrastructure."
        ],
        "summary": "Open technical databases are a rich source of reconnaissance data. Adversaries exploit public scan and certificate databases, passive DNS, and WHOIS to map victim infrastructure prior to attacks.",
        "remediation": "Audit and minimize exposure in scan engines and certificate registries. Harden DNS and CDN configurations to prevent unintentional data leakage.",
        "improvements": "Introduce continuous asset exposure monitoring. Enable alerts for third-party scans or certificate anomalies using CT log monitoring.",
        "mitre_version": "16.1"
    }
