def get_content():
    return {
        "id": "T1589.003",
        "url_id": "T1589/003",
        "title": "Gather Victim Identity Information: Employee Names",
        "description": "Adversaries may gather employee names that can be used during targeting. Employee names may be used to derive email addresses as well as to help guide other reconnaissance efforts and/or craft more-believable lures. Adversaries may easily gather employee names, since they may be readily available and exposed via online or other accessible data sets. Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and/or initial access.",
        "tags": ["reconnaissance", "identity-info", "employee-names"],
        "tactic": "Reconnaissance",
        "protocol": "HTTPS",
        "os": "Any",
        "tips": [
            "Monitor web traffic for automated scraping behavior",
            "Conduct regular reviews of exposed staff directories",
            "Use deception accounts to identify enumeration attempts"
        ],
        "data_sources": "Web Credential, Domain Name, Command, Cloud Service, Application Log",
        "log_sources": [
            {"type": "Web Credential", "source": "", "destination": ""},
            {"type": "Domain Name", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Cloud Service", "source": "", "destination": ""},
            {"type": "Application Log", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "AppData\\Roaming\\Mozilla\\Firefox\\Profiles", "identify": "Access to company directories and social platforms"},
            {"type": "Clipboard Data", "location": "RAM dump", "identify": "Copied names from public pages"}
        ],
        "destination_artifacts": [
            {"type": "Sysmon Logs", "location": "Event ID 1", "identify": "Execution of automated scraping tools"},
            {"type": "Windows Defender Logs", "location": "C:\\ProgramData\\Microsoft\\Windows Defender\\", "identify": "Tool-based activity or flagged macros/scripts"}
        ],
        "detection_methods": [
            "Detect scraping via abnormal volume of HTTP requests",
            "Alert on access to publicly available staff directories",
            "Monitor logins with dictionary-generated usernames"
        ],
        "apt": ["APT33", "APT35", "APT28"],
        "spl_query": [
            "index=web sourcetype=access_combined user_agent=*scrapy* OR user_agent=*python-requests*\n| stats count by src_ip, user_agent",
            "index=sysmon EventCode=1 CommandLine=*linkedin* OR CommandLine=*employee-directory*\n| stats count by CommandLine, User"
        ],
        "hunt_steps": [
            "Check for traffic patterns typical of scraping bots",
            "Look for repeated attempts to guess email formats",
            "Review cloud service logs for name enumeration patterns"
        ],
        "expected_outcomes": [
            "Early identification of actors gathering personnel identity data",
            "Detection of unusual access to staff directories"
        ],
        "false_positive": "Marketing tools and HR audits may perform similar activity—verify based on scheduling and authorized tool lists.",
        "clearing_steps": [
            "Clear browser history and local cached directories",
            "Delete temporary files created by reconnaissance scripts",
            "Flush DNS and clipboard data"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "T1586", "example": "Use names to create spoofed accounts for impersonation"},
            {"tactic": "Initial Access", "technique": "T1566", "example": "Send phishing emails using known employee names"}
        ],
        "watchlist": [
            "Unusual traffic to /about, /team, or /directory pages",
            "Use of open-source scraping frameworks",
            "Massive clipboard activity post-browsing"
        ],
        "enhancements": [
            "Deploy CAPTCHA or rate limiting on staff directories",
            "Create alerts for auto-generated email pattern lookups"
        ],
        "summary": "This technique outlines how adversaries collect employee name data from publicly available sources like company websites or social media to improve targeting accuracy in phishing or impersonation campaigns.",
        "remediation": "Remove excessive staff exposure from public platforms. Implement CAPTCHAs and monitor access to staff listings.",
        "improvements": "Cross-reference traffic to staff pages with behavioral analytics and deploy decoy employee entries to detect malicious intent.",
        "mitre_version": "16.1"
    }
