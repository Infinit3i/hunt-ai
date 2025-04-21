def get_content():
    return {
        "id": "T1590.001",
        "url_id": "T1590/001",
        "title": "Gather Victim Network Information: Domain Properties",
        "description": "Adversaries may gather information about the victim's network domain(s) that can be used during targeting. Information about domains and their properties may include a variety of details, including what domain(s) the victim owns as well as administrative data (ex: name, registrar, etc.) and more directly actionable information such as contacts (email addresses and phone numbers), business addresses, and name servers. Adversaries may gather this information in various ways, such as direct collection actions via Active Scanning or Phishing for Information. Information about victim domains and their properties may also be exposed to adversaries via online or other accessible data sets. Where third-party cloud providers are in use, this information may also be exposed through publicly available API endpoints, such as GetUserRealm and autodiscover in Office 365 environments. Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and/or initial access.",
        "tags": ["reconnaissance", "whois", "domain-properties", "cloud"],
        "tactic": "Reconnaissance",
        "protocol": "WHOIS, HTTPS",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Monitor WHOIS queries from uncommon sources",
            "Watch for discovery tools using GetUserRealm or autodiscover",
            "Limit exposure of domain registration data"
        ],
        "data_sources": "Domain Name, Internet Scan, Command, Cloud Service",
        "log_sources": [
            {"type": "Domain Name", "source": "", "destination": ""},
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Cloud Service", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "AppData\\Local\\Microsoft\\Edge\\User Data", "identify": "WHOIS and domain lookup tools"},
            {"type": "Command History", "location": "~/.bash_history", "identify": "Execution of whois or curl to endpoints like autodiscover"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Proxy Logs", "identify": "External queries to domain metadata services"},
            {"type": "Sysmon Logs", "location": "Event ID 3", "identify": "Execution of whois/resolve-dns APIs"}
        ],
        "detection_methods": [
            "Detect command-line usage of whois or similar tools",
            "Monitor for access to autodiscover or GetUserRealm endpoints",
            "Correlate cloud API access from unknown external IPs"
        ],
        "apt": ["APT28", "APT29"],
        "spl_query": [
            "index=sysmon EventCode=1 Image=*whois.exe* OR CommandLine=*GetUserRealm*\n| stats count by Image, CommandLine, User",
            "index=network sourcetype=proxy url=*autodiscover* OR url=*getuserrealm*\n| stats count by src_ip, url"
        ],
        "hunt_steps": [
            "Search for DNS and WHOIS enumeration tools",
            "Identify external IPs performing repeated domain info queries",
            "Audit access logs for known reconnaissance endpoints"
        ],
        "expected_outcomes": [
            "Detection of enumeration of owned domain and cloud details",
            "Discovery of misconfigured or exposed metadata services"
        ],
        "false_positive": "IT or red team assessments may perform similar lookups. Validate with team schedules or asset inventory systems.",
        "clearing_steps": [
            "Clear command history from terminal: history -c or rm ~/.bash_history",
            "Flush proxy logs and DNS cache",
            "Disable or restrict GetUserRealm and autodiscover exposure"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "T1583", "example": "Register similar domains based on WHOIS data"},
            {"tactic": "Initial Access", "technique": "T1566", "example": "Use discovered emails in phishing attacks"}
        ],
        "watchlist": [
            "Execution of domain enumeration tools",
            "Queries to public WHOIS APIs",
            "GetUserRealm or autodiscover endpoints accessed from unknown IPs"
        ],
        "enhancements": [
            "Use domain privacy protection on registrar platforms",
            "Alert on suspicious GET requests to Office365 discovery APIs"
        ],
        "summary": "This technique highlights how adversaries obtain registration and administrative details about victim-owned domains using WHOIS lookups, cloud service discovery endpoints, and metadata scraping, often as a precursor to more targeted reconnaissance or phishing.",
        "remediation": "Employ privacy registration on domains, limit public metadata exposure, and monitor for domain impersonation attempts.",
        "improvements": "Correlate WHOIS queries with threat intelligence on domain abuse and set up alerts for impersonated domains.",
        "mitre_version": "16.1"
    }
