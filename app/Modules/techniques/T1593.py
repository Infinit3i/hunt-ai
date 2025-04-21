def get_content():
    return {
        "id": "T1593",
        "url_id": "T1593",
        "title": "Search Open Websites/Domains",
        "description": "Adversaries may search freely available websites and domains for information about victims that can be used during targeting. These open sources may include social media, company websites, news articles, public press releases, government portals, contract award databases, and hiring pages. Information gathered may help in crafting phishing lures, selecting initial access vectors, or tailoring future operations.",
        "tags": ["reconnaissance", "osint", "target profiling"],
        "tactic": "Reconnaissance",
        "protocol": "HTTPS",
        "os": "",
        "tips": [
            "Regularly monitor organizational web presence to identify any exposed sensitive information.",
            "Scrub unnecessary details from job postings and public profiles that reveal technology stacks or infrastructure details.",
            "Monitor for adversary scanning activity using honeypots or passive DNS logging services."
        ],
        "data_sources": "Internet Scan, Domain Name, Persona, Application Log",
        "log_sources": [
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "Domain Name", "source": "", "destination": ""},
            {"type": "Persona", "source": "", "destination": ""},
            {"type": "Application Log", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "Browser cache and history logs", "identify": "Visited victim websites and social profiles"},
            {"type": "DNS Cache", "location": "Local resolver cache", "identify": "Domains queried for open information"}
        ],
        "destination_artifacts": [
            {"type": "Web Server Logs", "location": "Victim web infrastructure", "identify": "Recon crawlers or anomalous search behavior"},
            {"type": "Search Engine Logs", "location": "External aggregation platforms", "identify": "Metadata on searches of organizational domains"}
        ],
        "detection_methods": [
            "Use web server logs to identify aggressive scanning or directory brute forcing.",
            "Monitor search engine referrals to your site for indicators of reconnaissance.",
            "Flag web access from anonymizing services or threat actor-associated IPs."
        ],
        "apt": ["Star Blizzard", "GRU Unit 74455", "Unnamed PRC infrastructure threat actors"],
        "spl_query": [
            'index=web\n| search uri="*/careers*" OR uri="*/about*" OR uri="*/contracts*"\n| stats count by src_ip, uri'
        ],
        "hunt_steps": [
            "Review public-facing websites and online presence for overexposed information.",
            "Analyze WHOIS data, certificate transparency logs, and search engine indexing using OSINT tools.",
            "Correlate passive DNS data with known infrastructure and suspicious access patterns."
        ],
        "expected_outcomes": [
            "Detection of search patterns consistent with early-stage reconnaissance.",
            "Discovery of overshared or sensitive data in publicly accessible web content.",
            "Confirmation of social engineering risk exposure based on open content."
        ],
        "false_positive": "Web crawling and scraping tools used by legitimate marketing or SEO firms may mimic adversary behavior. Investigate based on context, frequency, and intent indicators.",
        "clearing_steps": [
            "Remove sensitive business information from public domains and job portals.",
            "Adjust robots.txt and implement access controls where possible.",
            "Use DLP tools and third-party OSINT platforms to track future leaks."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-data-exfiltration"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1566", "example": "Using details found on victim's website to send a spearphishing email"},
            {"tactic": "Resource Development", "technique": "T1585", "example": "Creating fake personas that mimic real staff listed on the site"}
        ],
        "watchlist": [
            "Frequent visits to specific directories like /admin, /contractors, or /employee-login",
            "New social media accounts or fake job listings mimicking the organization",
            "Excessive indexing by non-trusted bots"
        ],
        "enhancements": [
            "Deploy web application firewalls (WAF) with bot detection capabilities.",
            "Integrate Shodan/Google dorking checks into security audits.",
            "Automate scanning of external web presence for sensitive exposure."
        ],
        "summary": "Searching open websites and domains is a foundational reconnaissance step for adversaries. Information gathered through passive observation enables adversaries to develop targeting strategies, social engineering campaigns, or identify technical entry points for exploitation.",
        "remediation": "Redact technical details, names, and operational specifics from publicly accessible content. Conduct periodic audits of external web presence and adjust content accordingly.",
        "improvements": "Enhance monitoring of web infrastructure for enumeration and crawling. Strengthen awareness training to minimize unintentional disclosures via blogs, portfolios, or resumes.",
        "mitre_version": "16.1"
    }
