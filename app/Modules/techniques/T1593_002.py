def get_content():
    return {
        "id": "T1593.002",
        "url_id": "T1593/002",
        "title": "Search Open Websites/Domains: Search Engines",
        "description": "Adversaries may use search engines such as Google, Bing, or DuckDuckGo to discover information about victims. These engines often index websites, documents, and files unintentionally exposed to the internet. Attackers may use advanced search operators (Google Dorking) to locate misconfigured systems, login portals, sensitive documents, credentials, or other organizational data.",
        "tags": ["reconnaissance", "osint", "google dorking", "google hacking", "advanced search"],
        "tactic": "Reconnaissance",
        "protocol": "HTTPS",
        "os": "",
        "tips": [
            "Conduct periodic 'Google Dork' audits for your organization using queries like `site:yourdomain.com filetype:pdf` or `intitle:index.of`.",
            "Prevent indexing of sensitive directories/files using `robots.txt` and `noindex` meta tags.",
            "Monitor search engine results for your domain using brand protection or OSINT tools."
        ],
        "data_sources": "Internet Scan, File, Application Log",
        "log_sources": [
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Application Log", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "User browser cache", "identify": "Search queries like 'site:', 'filetype:', or 'intitle:' used for enumeration"},
            {"type": "Command History", "location": "~/.bash_history", "identify": "Search engine scraping or wget/curl downloads"}
        ],
        "destination_artifacts": [
            {"type": "Search Engine Cache", "location": "https://www.google.com/search", "identify": "Indexed organizational content"},
            {"type": "Public Document Repository", "location": "https://docs.google.com, https://s3.amazonaws.com", "identify": "Unsecured files discoverable via search"}
        ],
        "detection_methods": [
            "Monitor for rapid access attempts to multiple files exposed to search engines.",
            "Review web access logs for requests with known search engine user-agent strings targeting sensitive paths.",
            "Use canary tokens in exposed documents to detect adversary retrievals."
        ],
        "apt": ["APT41", "Muzabi"],
        "spl_query": [
            'index=web_proxy sourcetype=web\n| search uri_path="robots.txt" OR uri_path="sitemap.xml" OR uri="*filetype:xls*" OR uri="*intitle:index.of*"\n| stats count by src_ip, uri'
        ],
        "hunt_steps": [
            "Review indexed content using `site:<yourdomain.com>` and advanced operators.",
            "Check public paste and file sharing sites using company-specific keywords.",
            "Search for exposed email addresses, user credentials, or cloud storage links."
        ],
        "expected_outcomes": [
            "Detection of accidental data exposure indexed by search engines.",
            "Awareness of adversary reconnaissance activities leveraging search queries.",
            "Discovery of sensitive documents, credentials, or infrastructure information."
        ],
        "false_positive": "Automated tools and security scanners may mimic dorking patterns. Also, internal audits may produce similar logs. Validate actors and IP context before escalation.",
        "clearing_steps": [
            "Use `robots.txt` to exclude directories or files from indexing.",
            "Take down exposed content and invalidate URLs or tokens immediately.",
            "Submit removal requests to search engines to de-index sensitive files."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-leaked-credentials"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1078", "example": "Using harvested credentials found in exposed configuration files"},
            {"tactic": "Resource Development", "technique": "T1583", "example": "Using discovered infrastructure details to acquire similar assets"}
        ],
        "watchlist": [
            "Queries with `filetype:xls`, `inurl:admin`, or `intitle:index.of` targeting your domain",
            "Repeated requests to exposed S3 buckets or SharePoint documents from suspicious IPs"
        ],
        "enhancements": [
            "Implement automated Google Dork detection using tools like GitHub’s GitDorker or SearchDiggity.",
            "Integrate canary URLs or documents in public spaces to detect reconnaissance.",
            "Use services like SecurityTrails or Spyse to monitor digital footprint exposure."
        ],
        "summary": "Search engines are a powerful tool for adversaries seeking unintentionally exposed assets. By combining advanced queries with indexed data, they can locate leaked documents, misconfigured servers, and credentials. Proactive indexing management and periodic search audits are crucial defenses.",
        "remediation": "Identify and remove exposed content from the internet, submit de-indexing requests, and rotate credentials. Educate employees on the risks of publishing content without security review.",
        "improvements": "Create internal guidelines for public posting. Utilize automated scanners and reputation services to monitor external exposure.",
        "mitre_version": "16.1"
    }
