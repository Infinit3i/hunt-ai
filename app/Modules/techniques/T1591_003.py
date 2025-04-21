def get_content():
    return {
        "id": "T1591.003",
        "url_id": "T1591/003",
        "title": "Gather Victim Org Information: Identify Business Tempo",
        "description": "Adversaries may gather information about the victim's business tempo that can be used during targeting. Information about an organization’s business tempo may include operational hours, purchasing cycles, or shipment schedules. This data helps adversaries plan further reconnaissance or exploitation.",
        "tags": ["reconnaissance", "open-source-intelligence", "osint", "pre-attack", "external"],
        "tactic": "Reconnaissance",
        "protocol": "HTTP",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Monitor adversary use of public-facing business information.",
            "Track unusual interest in internal calendars or operational timelines.",
            "Use deception (e.g., honey calendars) to identify information gathering."
        ],
        "data_sources": "Web Credential, Command, Application Log, Internet Scan, User Account, Network Traffic, Persona",
        "log_sources": [
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Web Credential", "source": "", "destination": ""},
            {"type": "User Account", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "%APPDATA%\\Local\\Google\\Chrome\\User Data\\Default", "identify": "Indicates business hours researched"},
            {"type": "DNS Cache", "location": "ipconfig /displaydns", "identify": "Domain lookups for company info pages"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor for repeated access to publicly exposed business schedule data",
            "Correlate external queries to HR or event planning pages",
            "Detect use of automated scrapers or crawlers"
        ],
        "apt": ["APT28", "OceanLotus", "Charming Kitten"],
        "spl_query": [
            'index=proxy_logs uri="/calendar" OR uri="/events"\n| stats count by src_ip, uri',
            'index=web_logs uri="*about-us*" OR uri="*business-hours*"\n| stats count by user_agent, src_ip',
            'index=fw_logs dest_domain="*.companydomain.com" AND uri_path="/schedules"\n| stats count by src_ip'
        ],
        "hunt_steps": [
            "Identify external IPs that access business operation pages repeatedly",
            "Analyze user agents for automation signatures (e.g., curl, python-requests)",
            "Cross-reference traffic with marketing data exposures"
        ],
        "expected_outcomes": [
            "Detection of adversary-controlled IPs performing passive recon",
            "Correlated access patterns to specific time-based information",
            "Identification of potential phishing pretexts tailored to business schedules"
        ],
        "false_positive": "Legitimate external business partners may frequently access operational data pages. Correlate with known partner IPs or authenticated sessions.",
        "clearing_steps": [
            "Clear browser history and DNS cache on source machine:\nRun: ipconfig /flushdns\nClear: %APPDATA%\\Local\\Google\\Chrome\\User Data\\Default\\History",
            "Remove web access to internal operational calendars or restrict them via authentication"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Reconnaissance", "technique": "T1598", "example": "Phishing for Information"},
            {"tactic": "Initial Access", "technique": "T1195", "example": "Supply Chain Compromise"}
        ],
        "watchlist": [
            "External traffic accessing business-hour related URIs",
            "Automated user agents scraping org sites",
            "Public mentions of company calendar or schedule info"
        ],
        "enhancements": [
            "Deploy honeypot calendars to detect scraping",
            "Integrate external threat intel feeds for IPs tied to recon activity"
        ],
        "summary": "This technique involves gathering data on an organization's business rhythm to inform targeting strategies, phishing campaigns, or timing attacks for greater success.",
        "remediation": "Restrict access to internal scheduling data. Train staff to avoid publishing sensitive operational information. Implement web application firewalls to block scraping attempts.",
        "improvements": "Enforce user authentication for business-related information pages. Tag sensitive internal calendars or schedules with detection triggers.",
        "mitre_version": "16.1"
    }
