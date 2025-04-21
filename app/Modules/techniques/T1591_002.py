def get_content():
    return {
        "id": "T1591.002",
        "url_id": "T1591/002",
        "title": "Gather Victim Org Information: Business Relationships",
        "description": "Adversaries may gather information about the victim's business relationships that can be used during targeting. This may include third-party vendors, MSPs, contractors, or supply chain partners who have access to or connections with the target organization.",
        "tags": ["reconnaissance", "supply-chain", "partner-mapping", "external", "osint"],
        "tactic": "Reconnaissance",
        "protocol": "HTTP",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Review exposure of partner/vendor names on public sites and press releases.",
            "Monitor for mentions of internal partners or integrations on social media.",
            "Implement partner access controls based on the principle of least privilege."
        ],
        "data_sources": "Web Credential, Application Log, Internet Scan, Network Traffic, Domain Name, User Account, Persona",
        "log_sources": [
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Domain Name", "source": "", "destination": ""},
            {"type": "Application Log", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "%APPDATA%\\Local\\Google\\Chrome\\User Data\\Default", "identify": "Searches for vendor/partner domains"},
            {"type": "DNS Cache", "location": "ipconfig /displaydns", "identify": "Resolution of third-party supply chain domains"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Detect crawlers accessing vendor pages or supply chain mentions",
            "Monitor unusual frequency of requests to partner sections of the website",
            "Analyze patterns in third-party discovery traffic from suspicious IPs"
        ],
        "apt": ["Charming Kitten", "Berserk Bear", "APT28"],
        "spl_query": [
            'index=proxy_logs uri="*partners*" OR uri="*vendors*"\n| stats count by src_ip, uri',
            'index=web_logs uri="*/supply-chain/*" OR uri="*/third-party*"\n| stats count by user_agent, uri',
            'index=fw_logs dest_domain="*.vendor.com" OR dest_domain="*.partnerdomain.com"\n| stats count by src_ip'
        ],
        "hunt_steps": [
            "Search for traffic to known third-party URLs from unfamiliar IPs",
            "Look for partner-related domain enumeration or WHOIS lookups",
            "Analyze open-source datasets for leaked associations with the victim org"
        ],
        "expected_outcomes": [
            "Detection of attempts to enumerate the victim’s business partners",
            "Identification of reconnaissance targeting vendors or MSPs",
            "Alerts from correlation between partner visits and adversary-controlled infrastructure"
        ],
        "false_positive": "Legitimate business development tools or partner checks may exhibit similar access behavior. Whitelist known automation and CRM systems.",
        "clearing_steps": [
            "Flush browser and DNS cache:\nRun: ipconfig /flushdns\nClear: %APPDATA%\\Local\\Google\\Chrome\\User Data\\Default\\History",
            "Redact unnecessary mentions of partners from public documents and websites"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Reconnaissance", "technique": "T1598", "example": "Phishing for Information"},
            {"tactic": "Initial Access", "technique": "T1195", "example": "Supply Chain Compromise"},
            {"tactic": "Initial Access", "technique": "T1199", "example": "Trusted Relationship"}
        ],
        "watchlist": [
            "Vendor domain resolutions from previously unseen IPs",
            "Traffic patterns mimicking enumeration of business partner pages",
            "Suspicious external lookups of supply chain keywords"
        ],
        "enhancements": [
            "Create decoy vendor lists in publicly crawled pages to identify enumeration",
            "Use threat intelligence enrichment on partner enumeration attempts"
        ],
        "summary": "This technique focuses on the collection of business relationship data that adversaries can exploit to gain indirect access or map supply chains, often as a precursor to lateral or initial compromise.",
        "remediation": "Limit exposure of business partner details online. Use access segmentation for third parties. Review contracts to include security posture alignment with vendors.",
        "improvements": "Deploy WAF rules to alert on automated scraping behavior. Tag and classify web resources that mention business relationships.",
        "mitre_version": "16.1"
    }
