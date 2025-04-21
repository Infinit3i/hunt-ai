def get_content():
    return {
        "id": "T1591.004",
        "url_id": "T1591/004",
        "title": "Gather Victim Org Information: Identify Roles",
        "description": "Adversaries may gather information about identities and roles within the victim organization that can be used during targeting. This may reveal key personnel, their responsibilities, and access to sensitive resources.",
        "tags": ["reconnaissance", "organizational profiling", "identity targeting"],
        "tactic": "Reconnaissance",
        "protocol": "HTTPS",
        "os": "N/A",
        "tips": [
            "Monitor for excessive social media scraping behavior.",
            "Correlate HR-related data leaks with known APT reconnaissance phases."
        ],
        "data_sources": "Web Credential",
        "log_sources": [
            {"type": "Web Credential", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Application Log", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "%APPDATA%\\Browser\\History", "identify": "Visits to LinkedIn or org directories"},
            {"type": "Clipboard Data", "location": "Memory Dump", "identify": "Copy-pasted email lists or org charts"}
        ],
        "destination_artifacts": [
            {"type": "Event Logs", "location": "%SystemRoot%\\System32\\winevt\\Logs", "identify": "Scraping automation logs"}
        ],
        "detection_methods": [
            "Analyze browsing activity to job boards and professional networks",
            "Detect automated scraping tools via HTTP headers",
            "Monitor queries against internal org charts or directories"
        ],
        "apt": [
            "Lazarus Group", "DEV-0537", "Siamesekitten"
        ],
        "spl_query": [
            "index=web_logs uri_path=*linkedin* OR uri_path=*about-us* OR uri_path=*team*\n| stats count by src_ip, uri_path"
        ],
        "hunt_steps": [
            "Check outbound DNS and proxy logs for social network enumeration",
            "Identify traffic to career pages or leadership profiles",
            "Search clipboard dumps or browser caches for HR data"
        ],
        "expected_outcomes": [
            "Flagging of systems engaged in identity and role enumeration",
            "Visibility into targeted reconnaissance of key personnel"
        ],
        "false_positive": "Legitimate HR or marketing team activity may resemble reconnaissance behavior.",
        "clearing_steps": [
            "Clear clipboard: echo off | clip",
            "Purge browser history and cache",
            "Delete relevant prefetch: del /q C:\\Windows\\Prefetch\\*"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1566", "example": "Phishing emails crafted using org role insights"},
            {"tactic": "Resource Development", "technique": "T1585", "example": "Establish fake personas matching internal roles"}
        ],
        "watchlist": [
            "Repeated access to org/team pages",
            "Suspicious scraping of executive bios"
        ],
        "enhancements": [
            "Deploy rate-limiting and CAPTCHA on team pages",
            "Use canary tokens in org charts or directories"
        ],
        "summary": "Adversaries target public-facing information about internal roles to aid phishing, impersonation, or insider attacks.",
        "remediation": "Limit exposure of role-based data on public sites, implement behavioral-based detection of enumeration.",
        "improvements": "Cross-reference external scraping attempts with leaked credential alerts or HR records.",
        "mitre_version": "16.1"
    }