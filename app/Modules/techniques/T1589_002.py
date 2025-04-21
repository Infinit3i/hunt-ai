def get_content():
    return {
        "id": "T1589.002",
        "url_id": "T1589/002",
        "title": "Gather Victim Identity Information: Email Addresses",
        "description": "Adversaries may gather email addresses that can be used during targeting. Even if internal instances exist, organizations may have public-facing email infrastructure and addresses for employees. Adversaries may easily gather email addresses, since they may be readily available and exposed via online or other accessible data sets. Email addresses could also be enumerated via more active means, such as probing and analyzing responses from authentication services that may reveal valid usernames in a system. For example, adversaries may be able to enumerate email addresses in Office 365 environments by querying a variety of publicly available API endpoints, such as autodiscover and GetCredentialType. Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and/or initial access.",
        "tags": ["reconnaissance", "email-addresses", "identity-info"],
        "tactic": "Reconnaissance",
        "protocol": "HTTPS, SMTP, IMAP, API",
        "os": "Any",
        "tips": [
            "Rate-limit and monitor access to autodiscover and credential-type endpoints",
            "Obfuscate email directory listings on public websites",
            "Monitor for excessive authentication attempts using invalid usernames"
        ],
        "data_sources": "Network Traffic, Web Credential, Cloud Service, Command, Application Log",
        "log_sources": [
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Web Credential", "source": "", "destination": ""},
            {"type": "Cloud Service", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Application Log", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "UserProfile\\AppData\\Local\\Microsoft\\Edge", "identify": "Access to staff email directories or pastebin dumps"},
            {"type": "Clipboard Data", "location": "RAM", "identify": "Harvested email lists temporarily copied"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Firewall Logs", "identify": "Outbound calls to Office365 or Exchange endpoints"},
            {"type": "Sysmon Logs", "location": "Event ID 3", "identify": "API or script-based enumeration activity"}
        ],
        "detection_methods": [
            "Monitor access patterns to autodiscover/GetCredentialType APIs",
            "Alert on bulk email pattern matching in web traffic",
            "Detect repeated failed login attempts with guessed usernames"
        ],
        "apt": ["TA427", "OceanLotus", "Kimsuky", "TA453", "EXOTIC LILY", "Moonstone Sleet"],
        "spl_query": [
            "index=network sourcetype=proxy url=*autodiscover* OR url=*getcredentialtype*\n| stats count by src_ip, url",
            "index=cloud sourcetype=auth action=failure\n| stats count by src_ip, user, uri_path"
        ],
        "hunt_steps": [
            "Search for Office365 endpoint hits from unusual geo locations",
            "Identify failed login patterns that resemble enumeration attempts",
            "Correlate access to email directory-like URLs with user-agent anomalies"
        ],
        "expected_outcomes": [
            "Detection of email enumeration or directory scraping",
            "Behavioral indicators of credential harvesting preparation"
        ],
        "false_positive": "Legitimate password reset flows, internal diagnostics tools, or red team activity—validate with IT/security teams.",
        "clearing_steps": [
            "Clear browser and clipboard artifacts",
            "Purge logs of tools/scripts used to enumerate emails",
            "Revoke tokens tied to suspicious API access"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "T1586/002", "example": "Create email accounts for spoofing based on harvested names"},
            {"tactic": "Initial Access", "technique": "T1566", "example": "Craft phishing campaigns targeting collected email addresses"}
        ],
        "watchlist": [
            "Autodiscover and GetCredentialType requests",
            "Multiple failed auths with incrementing usernames",
            "Traffic to leaked credential paste sites"
        ],
        "enhancements": [
            "Enable anomaly detection on Office365 API usage",
            "Deploy deception email entries in public staff listings"
        ],
        "summary": "This subtechnique describes how adversaries collect valid email addresses through passive gathering, online exposure, or active enumeration of authentication services. Collected emails are typically used in follow-on phishing, spoofing, or brute-force attacks.",
        "remediation": "Limit exposure of email addresses on public domains. Employ validation, CAPTCHA, and alerting on Office365 enumeration endpoints.",
        "improvements": "Integrate threat intelligence to auto-block repeated email enumeration sources and flag suspected enumeration APIs.",
        "mitre_version": "16.1"
    }
