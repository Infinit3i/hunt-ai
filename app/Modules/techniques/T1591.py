def get_content():
    return {
        "id": "T1591",
        "url_id": "T1591",
        "title": "Gather Victim Org Information",
        "description": "Adversaries may gather information about the victim's organization that can be used during targeting. This includes details such as organizational structure, business operations, and key personnel. These insights may enable further stages of attack, such as social engineering, phishing, or exploitation of trusted relationships.",
        "tags": ["reconnaissance", "osint", "organizational-mapping", "pre-attack"],
        "tactic": "Reconnaissance",
        "protocol": "HTTP",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Monitor for patterns of interest in public-facing org charts and bios.",
            "Educate employees about oversharing on social media platforms.",
            "Audit publicly available documents for excessive operational detail."
        ],
        "data_sources": "Web Credential, Domain Name, Command, Application Log, Persona, User Account, Internet Scan, Social Media",
        "log_sources": [
            {"type": "Web Credential", "source": "", "destination": ""},
            {"type": "Domain Name", "source": "", "destination": ""},
            {"type": "User Account", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "%APPDATA%\\Local\\Google\\Chrome\\User Data\\Default", "identify": "Access to leadership pages, org charts"},
            {"type": "Clipboard Data", "location": "RAM artifacts", "identify": "Copied details from internal profiles or org references"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Detect abnormal requests for 'about-us' or leadership pages",
            "Monitor for scraping patterns from external IPs",
            "Analyze log data for enumeration of internal role-based pages"
        ],
        "apt": ["Lazarus Group", "ThreatNeedle", "Moonstone Sleet", "Muzabi"],
        "spl_query": [
            'index=web_logs uri="*about-us*" OR uri="*leadership*"\n| stats count by src_ip, user_agent',
            'index=proxy_logs uri="*org-structure*" OR uri="*company-hierarchy*"\n| stats count by uri, src_ip',
            'index=application_logs "OrgChartAccess"\n| stats count by src_user'
        ],
        "hunt_steps": [
            "Identify unusual IPs accessing org charts or team pages",
            "Trace account enumeration attempts in web application logs",
            "Search for phishing emails mentioning internal divisions or departments"
        ],
        "expected_outcomes": [
            "Detection of reconnaissance activity focused on org structure",
            "Profiling of adversary interest in specific teams or roles",
            "Early warning for phishing or social engineering operations"
        ],
        "false_positive": "Job seekers or legitimate recruiters may access leadership and team structure pages. Filter by IP reputation and request patterns.",
        "clearing_steps": [
            "Clear DNS cache and local file traces related to access:\nRun: ipconfig /flushdns\nDelete: %APPDATA%\\Chrome\\User Data\\Default\\History",
            "Review and redact overshared info from public resources"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Reconnaissance", "technique": "T1598", "example": "Phishing for Information"},
            {"tactic": "Resource Development", "technique": "T1585", "example": "Establish Accounts"},
            {"tactic": "Initial Access", "technique": "T1199", "example": "Trusted Relationship"}
        ],
        "watchlist": [
            "Frequent hits to org structure or leadership URLs",
            "User agents indicative of scraping tools",
            "Search activity around internal roles or departments"
        ],
        "enhancements": [
            "Deploy honeypot leadership bios to monitor enumeration attempts",
            "Use anti-scraping techniques on public directories"
        ],
        "summary": "This technique involves gathering general or specific information about an organization's structure, personnel, and operations, which can be used to support social engineering, impersonation, or strategic attack timing.",
        "remediation": "Limit exposure of sensitive org structure details. Train staff on limiting public professional footprint. Secure internal org charts behind authentication.",
        "improvements": "Use content tagging to flag sensitive data exposure. Establish anomaly detection for org info page access patterns.",
        "mitre_version": "16.1"
    }
