def get_content():
    return {
        "id": "T1590.002",
        "url_id": "T1590/002",
        "title": "Gather Victim Network Information: DNS",
        "description": "Adversaries may gather information about the victim's DNS that can be used during targeting. DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts. DNS MX, TXT, and SPF records may also reveal the use of third party cloud and SaaS providers, such as Office 365, G Suite, Salesforce, or Zendesk. Adversaries may gather this information in various ways, such as querying or otherwise collecting details via DNS/Passive DNS. DNS information may also be exposed to adversaries via online or other accessible data sets. Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and/or initial access. Adversaries may also use DNS zone transfer (DNS query type AXFR) to collect all records from a misconfigured DNS server.",
        "tags": ["reconnaissance", "dns", "passive-dns", "zone-transfer"],
        "tactic": "Reconnaissance",
        "protocol": "DNS",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Monitor for large DNS queries or AXFR attempts",
            "Block DNS zone transfers from external IPs",
            "Use DNS monitoring to detect abnormal record queries"
        ],
        "data_sources": "DNS, Internet Scan, Domain Name, Command",
        "log_sources": [
            {"type": "DNS", "source": "", "destination": ""},
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "Domain Name", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "DNS Cache", "location": "/var/cache/bind", "identify": "Resolver cache for past lookups"},
            {"type": "Browser History", "location": "AppData\\Local\\Google\\Chrome\\User Data\\Default", "identify": "URLs and domains accessed"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Firewall Logs", "identify": "Outbound DNS lookups"},
            {"type": "Sysmon Logs", "location": "Event ID 3", "identify": "Suspicious DNS query tools like dig or nslookup"}
        ],
        "detection_methods": [
            "Monitor for use of DNS AXFR query types",
            "Alert on large bursts of DNS queries for subdomain enumeration",
            "Detect unusual outbound DNS queries to uncommon domains"
        ],
        "apt": ["Volt Typhoon"],
        "spl_query": [
            "index=dns sourcetype=*dns* query_type=AXFR\n| stats count by src_ip, dest_ip, query",
            "index=sysmon EventCode=1 Image=*nslookup.exe* OR Image=*dig.exe*\n| stats count by Image, CommandLine, User"
        ],
        "hunt_steps": [
            "Identify excessive or recursive DNS requests from endpoints",
            "Check firewall logs for DNS zone transfer attempts",
            "Search for common enumeration tools in endpoint telemetry"
        ],
        "expected_outcomes": [
            "Discovery of external DNS enumeration attempts",
            "Zone transfer misuse on public-facing DNS infrastructure"
        ],
        "false_positive": "DNS admins testing server configs or security researchers. Validate tool usage and IP origin.",
        "clearing_steps": [
            "Flush DNS cache: ipconfig /flushdns or systemd-resolve --flush-caches",
            "Remove nslookup/dig logs: Clear command history or rotate audit logs",
            "Restart DNS services and audit for security misconfigurations"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1133", "example": "Use DNS records to locate and access remote services"},
            {"tactic": "Resource Development", "technique": "T1583", "example": "Register infrastructure mimicking discovered DNS records"}
        ],
        "watchlist": [
            "Use of dig, host, or nslookup tools on endpoints",
            "AXFR requests to public DNS servers",
            "High-volume DNS queries from a single host"
        ],
        "enhancements": [
            "Implement DNS RPZ (Response Policy Zones)",
            "Enforce logging of DNS query volume and patterns"
        ],
        "summary": "This technique captures adversary efforts to extract DNS record data from public or misconfigured name servers. DNS records can reveal internal subdomains, cloud usage, or mail routes, giving attackers valuable intelligence for further targeting.",
        "remediation": "Disable public-facing DNS zone transfers, monitor DNS for anomalous queries, and apply DNSSEC for validation integrity.",
        "improvements": "Integrate passive DNS logging tools and block unauthorized outbound DNS over port 53 and 853 using firewalls.",
        "mitre_version": "16.1"
    }
