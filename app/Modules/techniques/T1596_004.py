def get_content():
    return {
        "id": "T1596.004",
        "url_id": "T1596/004",
        "title": "Search Open Technical Databases: CDNs",
        "description": "Adversaries may search content delivery network (CDN) data about victims that can be used during targeting. Publicly available CDN data or misconfigured assets may reveal sensitive files, infrastructure details, or geographic distribution patterns of hosted resources.",
        "tags": ["cdn", "reconnaissance", "cloud exposure", "open data"],
        "tactic": "Reconnaissance",
        "protocol": "HTTP, HTTPS",
        "os": "",
        "tips": [
            "Use CDN access control lists to prevent unauthorized public indexing of sensitive directories.",
            "Audit CDN configurations regularly for unintended file exposure.",
            "Minimize metadata leakage in CDN-distributed content (e.g., filenames, tokens, debug pages)."
        ],
        "data_sources": "Cloud Storage, Web Credential, Network Traffic, Asset",
        "log_sources": [
            {"type": "Cloud Storage", "source": "", "destination": ""},
            {"type": "Web Credential", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Asset", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "Adversary Workstation", "identify": "CDN endpoint lookups or file probing"},
            {"type": "DNS Cache", "location": "Adversary Device", "identify": "Resolved CDN edge nodes or URLs with content leaks"}
        ],
        "destination_artifacts": [
            {"type": "URL History", "location": "Edge Server Logs", "identify": "Access to misconfigured or leaked file paths"},
            {"type": "Network Connections", "location": "Organization’s CDN tenant", "identify": "Inbound IPs probing CDN storage directly"}
        ],
        "detection_methods": [
            "Monitor for excessive requests or brute-force attempts on CDN-hosted paths.",
            "Analyze CDN logs for anomalies in geo-distribution and access times.",
            "Track public indexers or scrapers targeting your CDN subdomains."
        ],
        "apt": [],
        "spl_query": [
            'index=cdn_access_logs\n| search status_code=200 AND uri_path IN ("/config", "/admin", "/secrets")\n| stats count by src_ip, uri_path, user_agent'
        ],
        "hunt_steps": [
            "Check your CDN tenant for anonymously accessible paths or unsecured links.",
            "Identify sensitive file types (e.g., `.bak`, `.conf`, `.json`) being requested by unknown clients.",
            "Investigate user agents mimicking scrapers or automated probes."
        ],
        "expected_outcomes": [
            "Detection of adversary efforts to exploit CDN-exposed misconfigurations.",
            "Prevention of sensitive resource indexing by external scanners."
        ],
        "false_positive": "Web developers or SEO tools may interact with CDN-hosted content for performance testing or validation purposes.",
        "clearing_steps": [
            "Remove or restrict public access to exposed CDN resources.",
            "Enable authentication or tokenization for sensitive paths.",
            "Invalidate caches where old or leaked content may persist."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-data-exfiltration"
        ],
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "T1583", "example": "Adversary acquires infrastructure mimicking CDN behavior"},
            {"tactic": "Initial Access", "technique": "T1189", "example": "Access to leaked login portals or misconfigured content on CDN"}
        ],
        "watchlist": [
            "CDN access from previously unseen or low-reputation geographies",
            "Requests for deprecated or unlinked assets on CDN subdomains",
            "Unusual file extensions (e.g., `.sql`, `.key`, `.pem`) accessed via CDN"
        ],
        "enhancements": [
            "Tag sensitive CDN directories and enable alerting on unauthorized access.",
            "Create honeypot CDN entries to detect enumeration attempts.",
            "Use robots.txt or CDN-level metadata to block scanning bots."
        ],
        "summary": "Adversaries may search or exploit CDN infrastructure to access sensitive organizational content. Misconfigurations in CDN-hosted content can unintentionally expose login pages, admin portals, or internal assets, giving attackers valuable reconnaissance information.",
        "remediation": "Audit CDN configurations, restrict public file access, and implement secure CDN deployment practices such as tokenization and logging.",
        "improvements": "Implement geo-restrictions and rate-limiting on CDN access patterns. Periodically simulate adversary discovery attempts using open source tools.",
        "mitre_version": "16.1"
    }
