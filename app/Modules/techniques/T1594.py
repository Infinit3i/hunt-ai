def get_content():
    return {
        "id": "T1594",
        "url_id": "T1594",
        "title": "Search Victim-Owned Websites",
        "description": "Adversaries may search websites owned by the victim to collect information for use in targeting operations. These websites often contain employee names, roles, email addresses, department information, and operational insights. Attackers may manually browse sites or use automated tools to discover hidden files, directories, or vulnerable endpoints.",
        "tags": ["reconnaissance", "osint", "web", "targeting", "victim-website"],
        "tactic": "Reconnaissance",
        "protocol": "HTTP/HTTPS",
        "os": "",
        "tips": [
            "Review your organization's public website content and metadata regularly.",
            "Restrict access to sensitive files such as admin panels, sitemaps, and directory listings.",
            "Use robots.txt and authentication where appropriate, but do not assume it will prevent access by adversaries."
        ],
        "data_sources": "Application Log",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "Adversary Workstation", "identify": "Access to victim's website, hidden pages, or contact directories"},
            {"type": "Command History", "location": "~/.bash_history", "identify": "Use of curl, wget, gobuster, dirb to scrape or brute-force directories"}
        ],
        "destination_artifacts": [
            {"type": "Web Server Logs", "location": "/var/log/apache2/access.log", "identify": "User-agents or IPs indicative of automated directory scanning or web scraping"}
        ],
        "detection_methods": [
            "Monitor web access logs for anomalies such as excessive requests from a single IP or user-agent string.",
            "Analyze traffic for patterns typical of automated web crawlers (e.g., gobuster, dirb, curl, python scripts).",
            "Watch for access to robots.txt, sitemap.xml, and other metadata files that may indicate reconnaissance activity."
        ],
        "apt": ["Silent Librarian", "Ivanti Exploiters", "EXOTIC LILY", "APT41", "Muzabi"],
        "spl_query": [
            'index=web_logs sourcetype=access_combined\n| search uri IN ("/robots.txt", "/sitemap.xml") OR user_agent IN ("curl", "python", "gobuster", "dirb")\n| stats count by src_ip, uri, user_agent'
        ],
        "hunt_steps": [
            "Correlate IPs that access sensitive or rarely visited paths (e.g., /admin, /internal).",
            "Look for unusual crawlers or scanning activity against your public websites.",
            "Cross-reference web traffic with threat intel for known adversary infrastructure."
        ],
        "expected_outcomes": [
            "Detection of pre-attack reconnaissance from threat actors.",
            "Identification of public exposure of sensitive information.",
            "Mitigation of data leakage vectors through web content."
        ],
        "false_positive": "Search engine crawlers and legitimate bots may trigger similar patterns. Validate using known bot lists or headers.",
        "clearing_steps": [
            "Remove unnecessary public exposure of sensitive data.",
            "Restrict access to admin panels and staging areas via authentication and IP whitelisting.",
            "Use `.htaccess` or firewall rules to rate-limit or block suspicious scanners."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-web-defacement"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1566", "example": "Using employee emails found on a website to craft spearphishing payloads"},
            {"tactic": "Resource Development", "technique": "T1585", "example": "Registering accounts impersonating departments listed on a target’s webpage"}
        ],
        "watchlist": [
            "Repeated access to metadata files (robots.txt, sitemap.xml)",
            "Access attempts to directories not linked from any page",
            "Requests from anonymous networks like Tor or bulletproof VPS ranges"
        ],
        "enhancements": [
            "Implement web application firewalls (WAF) with custom rules for reconnaissance behavior.",
            "Track changes to publicly exposed web content using website monitoring tools.",
            "Deploy honeypot files or pages to detect scanning or crawling behavior."
        ],
        "summary": "Adversaries frequently analyze publicly available websites owned by the target to extract operational or personnel data for further intrusion planning. These sites may reveal key organizational details, hidden directories, or contact information that can facilitate phishing, impersonation, or technical attacks.",
        "remediation": "Limit exposure of sensitive operational details on websites, restrict access to administrative areas, and monitor for abnormal browsing activity. Use obscurity, access controls, and frequent audits to harden public assets.",
        "improvements": "Automate review of public content and integrate WAF and SIEM alerts for web reconnaissance. Educate web content teams about OSINT risks.",
        "mitre_version": "16.1"
    }
