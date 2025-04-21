def get_content():
    return {
        "id": "T1593.001",
        "url_id": "T1593/001",
        "title": "Search Open Websites/Domains: Social Media",
        "description": "Adversaries may search social media platforms for information about victims that can be used during targeting. Platforms such as LinkedIn, Facebook, Twitter (X), Instagram, and others may reveal valuable insights about an organization, including employee roles, locations, job changes, business operations, and personal interests. This information can be used to craft more effective social engineering campaigns or to identify potential technical weaknesses.",
        "tags": ["reconnaissance", "social engineering", "osint", "persona building"],
        "tactic": "Reconnaissance",
        "protocol": "HTTPS",
        "os": "",
        "tips": [
            "Audit social media activity regularly to ensure no sensitive information is inadvertently posted.",
            "Train employees on best practices for secure social media usage and how to spot impersonation attempts.",
            "Use identity monitoring services to track for impersonation or cloning of executive/employee accounts."
        ],
        "data_sources": "Persona, Internet Scan, Application Log, Network Traffic",
        "log_sources": [
            {"type": "Persona", "source": "", "destination": ""},
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "Web browser cache", "identify": "Access to social media URLs of employee profiles"},
            {"type": "Clipboard Data", "location": "Temporary memory", "identify": "Copied employee data from social platforms"}
        ],
        "destination_artifacts": [
            {"type": "Social Media Platform Logs", "location": "Facebook/LinkedIn profile analytics", "identify": "Profile views or suspicious DMs"},
            {"type": "Cloud Storage", "location": "Online persona documentation", "identify": "Colleted screenshots or exported data"}
        ],
        "detection_methods": [
            "Monitor for anomalous access to public profiles from foreign IPs or automated tools.",
            "Track suspicious social engineering messages reported by employees.",
            "Use digital risk protection (DRP) services to scan for impersonated accounts."
        ],
        "apt": ["Lazarus", "Kimsuky", "EXOTIC LILY"],
        "spl_query": [
            'index=email OR index=web_proxy\n| search uri="*linkedin.com*" OR uri="*facebook.com*" OR uri="*twitter.com*"\n| stats count by src_ip, uri, user'
        ],
        "hunt_steps": [
            "Enumerate social media profiles associated with the organization using tools like Maltego or SpiderFoot.",
            "Check for executive or employee impersonation across platforms.",
            "Investigate anomalous direct messages or connection requests reported internally."
        ],
        "expected_outcomes": [
            "Identification of sensitive personal or organizational information available online.",
            "Detection of impersonation attempts or malicious engagement with employee profiles.",
            "Evidence of reconnaissance activity related to phishing preparation or targeting."
        ],
        "false_positive": "Legitimate usage of social media platforms by staff may resemble reconnaissance activity. Focus on detecting impersonation, automation, or unusual source behavior.",
        "clearing_steps": [
            "Request takedown of fake accounts via platform reporting mechanisms.",
            "Contact platform security teams directly for escalated impersonation cases.",
            "Have affected employees update security settings and notify contacts."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-identity-theft"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1566.003", "example": "Using social media to deliver a spearphishing message with malicious links"},
            {"tactic": "Resource Development", "technique": "T1585", "example": "Creating fake personas to gather information or build trust"}
        ],
        "watchlist": [
            "New LinkedIn profiles claiming affiliation with the organization",
            "Multiple access attempts to executive social media pages from foreign IPs",
            "Employee-reported suspicious messages or job offers"
        ],
        "enhancements": [
            "Deploy internal OSINT tools to monitor public platforms for leaked or sensitive info.",
            "Implement security awareness training specific to social media threats.",
            "Use sentiment analysis and topic monitoring to detect early signs of targeting."
        ],
        "summary": "Social media platforms offer a wealth of data for adversaries conducting reconnaissance. By analyzing employee profiles, company pages, and group interactions, attackers can craft believable lures or identify strategic weaknesses in an organization’s people layer.",
        "remediation": "Tighten privacy settings on employee accounts, educate staff on impersonation risks, and establish clear escalation paths for reporting suspicious social activity.",
        "improvements": "Integrate social media monitoring into your overall threat intelligence program. Track profile changes, impersonations, and suspicious content referencing your brand.",
        "mitre_version": "16.1"
    }
