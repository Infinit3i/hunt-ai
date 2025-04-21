def get_content():
    return {
        "id": "T1596.005",
        "url_id": "T1596/005",
        "title": "Search Open Technical Databases: Scan Databases",
        "description": "Adversaries may search within public scan databases for information about victims that can be used during targeting. These databases, such as Shodan and Censys, contain historical and real-time data on Internet-facing systems including open ports, banners, services, and SSL certificates.",
        "tags": ["shodan", "censys", "internet scan", "open source intelligence", "osint"],
        "tactic": "Reconnaissance",
        "protocol": "HTTP, HTTPS, DNS",
        "os": "",
        "tips": [
            "Monitor public exposure of critical infrastructure using tools like Shodan or Censys.",
            "Ensure server banners, metadata, and error messages do not reveal sensitive details.",
            "Regularly audit attack surface to ensure unintentional exposure is minimized."
        ],
        "data_sources": "Internet Scan, Certificate, Network Traffic, Asset",
        "log_sources": [
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "Certificate", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Asset", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "Attacker's system", "identify": "Access to scan.shodan.io or search.censys.io"},
            {"type": "DNS Cache", "location": "Attacker’s system", "identify": "Lookups related to scan API endpoints or indexed IPs"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Scanned targets", "identify": "Traffic from Shodan/Censys sensors or test probes"},
            {"type": "Certificates", "location": "Exposed services", "identify": "Public keys or organizational data seen in scan databases"}
        ],
        "detection_methods": [
            "Monitor for excessive or abnormal interest in externally-facing IPs following publication to scan databases.",
            "Track DNS resolution logs to identify repeated lookups from external scanning services.",
            "Inspect logs for queries that follow the typical signature of Shodan/Censys access patterns."
        ],
        "apt": [
            "APT41"
        ],
        "spl_query": [
            'index=network_traffic\n| search src_ip IN (shodan_ip_list, censys_ip_list)\n| stats count by dest_ip, dest_port, src_ip'
        ],
        "hunt_steps": [
            "Review scan database entries for your public-facing infrastructure.",
            "Identify any new or unusual entries that coincide with observed probing behavior.",
            "Match scan data fields (e.g., SSL CN fields, server banners) with internal inventory."
        ],
        "expected_outcomes": [
            "Awareness of which assets are publicly indexed and visible to adversaries.",
            "Early detection of adversaries initiating further stages post-scan research."
        ],
        "false_positive": "Security researchers and red teams may also use public scan databases. Confirm intent through IP reputation and behavioral analysis.",
        "clearing_steps": [
            "Harden external services to reduce exposed metadata or misconfigurations.",
            "Update TLS/SSL certificates with anonymized fields if not required to be public.",
            "Engage with scan vendors to delist sensitive assets where possible."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-threatintel"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1190", "example": "Adversary discovers a vulnerable server version from a scan result and exploits it"},
            {"tactic": "Resource Development", "technique": "T1587", "example": "Adversary uses scan insights to build infrastructure mimicking target environment"}
        ],
        "watchlist": [
            "Incoming traffic from known scanning engines post-publication",
            "Public exposure of critical infrastructure in search engines",
            "Repeated recon on the same services (ports, banners, SSL data)"
        ],
        "enhancements": [
            "Set up alerting for new entries involving your domains or IPs in scan databases.",
            "Automate parsing of scan engine APIs to detect newly indexed infrastructure.",
            "Deploy decoy systems (honeynets) to monitor scan-based access."
        ],
        "summary": "This technique involves using publicly available scan databases like Shodan to gather exposed information about an organization’s infrastructure. These sources allow attackers to plan targeted attacks with high precision, often without active scanning themselves.",
        "remediation": "Audit all externally facing assets and ensure configurations limit unnecessary data leakage. Use infrastructure monitoring tools to regularly scan your own environment from an attacker’s perspective.",
        "improvements": "Include public scan database monitoring in your security operations. Tag high-sensitivity systems and restrict exposure using access controls, VPNs, and TLS inspection.",
        "mitre_version": "16.1"
    }
