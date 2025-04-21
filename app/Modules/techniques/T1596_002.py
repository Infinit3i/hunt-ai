def get_content():
    return {
        "id": "T1596.002",
        "url_id": "T1596/002",
        "title": "Search Open Technical Databases: WHOIS",
        "description": "Adversaries may search public WHOIS data for information about victims that can be used during targeting. WHOIS databases store domain registration information and may reveal names, phone numbers, email addresses, IP blocks, and DNS details useful for reconnaissance.",
        "tags": ["whois", "domain reconnaissance", "osint", "registrar", "dns enumeration"],
        "tactic": "Reconnaissance",
        "protocol": "WHOIS",
        "os": "",
        "tips": [
            "Use WHOIS privacy protection when registering domains to obscure contact and organizational information.",
            "Monitor your organization's domains for WHOIS lookups using threat intelligence sources.",
            "Rotate and redact administrative contact details when possible."
        ],
        "data_sources": "Domain Name, Internet Scan, Asset, Command",
        "log_sources": [
            {"type": "Domain Name", "source": "", "destination": ""},
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "Asset", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Command History", "location": "~/.bash_history", "identify": "Use of whois or dig commands"},
            {"type": "Browser History", "location": "Adversary Browser", "identify": "WHOIS web portal queries"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "WHOIS Service", "identify": "WHOIS server queries (port 43 or web-based APIs)"}
        ],
        "detection_methods": [
            "Monitor for repeated queries from a single IP targeting WHOIS web services.",
            "Use threat intel feeds to correlate IPs performing reconnaissance on WHOIS with known bad actors.",
            "Check your own domain WHOIS lookups if your provider logs access requests."
        ],
        "apt": [],
        "spl_query": [
            'index=proxy_logs OR index=dns\n| search uri_domain IN ("whois.domaintools.com", "who.is", "viewdns.info")\n| stats count by src_ip, uri_domain'
        ],
        "hunt_steps": [
            "Enumerate WHOIS data exposure across all your registered domains.",
            "Search for domains where WHOIS exposure includes personal or corporate emails.",
            "Correlate known phishing or reconnaissance attempts with domain contact data leakage."
        ],
        "expected_outcomes": [
            "Identify potential organizational exposure through domain registrant data.",
            "Prevent impersonation or spearphishing attacks leveraging exposed WHOIS contact details."
        ],
        "false_positive": "Domain resellers, internal compliance scans, or legitimate uptime monitors may query WHOIS records regularly.",
        "clearing_steps": [
            "Enable WHOIS privacy on all public domains.",
            "Use generic aliases instead of personal or org-specific emails in registrant information.",
            "Rotate exposed contact data if previously leaked."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-data-exfiltration"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1199", "example": "Impersonation of a registrant using leaked WHOIS email"},
            {"tactic": "Resource Development", "technique": "T1583", "example": "Spoofing domains based on similar WHOIS-discovered patterns"}
        ],
        "watchlist": [
            "Multiple WHOIS lookups in short succession",
            "WHOIS lookups paired with passive DNS enumeration",
            "New domains registered that mimic your WHOIS registrant name or org"
        ],
        "enhancements": [
            "Leverage registrar-provided WHOIS monitoring tools.",
            "Include WHOIS contact data in DLP policies and alerts.",
            "Deploy decoy domains with fake WHOIS to detect adversary interest."
        ],
        "summary": "WHOIS data offers adversaries insight into domain ownership, infrastructure, and contacts. Even basic exposure of nameservers or admin emails can lead to phishing or further targeting.",
        "remediation": "Mask sensitive WHOIS fields with privacy guards, use pseudonyms or generic contact methods, and rotate registration details regularly.",
        "improvements": "Integrate WHOIS monitoring with SIEM and threat intelligence for alerting. Educate employees to use redacted WHOIS data when registering new assets.",
        "mitre_version": "16.1"
    }
