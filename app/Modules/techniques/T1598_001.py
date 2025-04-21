def get_content():
    return {
        "id": "T1598.001",
        "url_id": "T1598/001",
        "title": "Phishing for Information: Spearphishing Service",
        "description": "Adversaries may send spearphishing messages via third-party services to elicit sensitive information that can be used during targeting. These services include social media platforms, personal email, and messaging apps which often lack the security controls of enterprise environments. The attacker’s objective is to gain the trust of the target and solicit information by impersonating a legitimate opportunity or inquiry.",
        "tags": ["spearphishing", "social engineering", "reconnaissance", "social media"],
        "tactic": "Reconnaissance",
        "protocol": "Web/HTTP(S), Messaging API",
        "os": "",
        "tips": [
            "Encourage employees to avoid discussing sensitive information on non-corporate platforms.",
            "Monitor for impersonated corporate accounts or recruitment messages on social media.",
            "Educate users to report suspicious messages received through personal communication channels."
        ],
        "data_sources": "Application Log, Network Traffic",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "User Device", "identify": "Access to fake social media profiles"},
            {"type": "Clipboard Data", "location": "System Memory", "identify": "Copied profile URLs or message text"}
        ],
        "destination_artifacts": [
            {"type": "Message Logs", "location": "Third-party services (e.g., LinkedIn, Gmail)", "identify": "Messages requesting sensitive internal information"}
        ],
        "detection_methods": [
            "Track for impersonation or recruitment-related communication on public platforms.",
            "Use threat intel services to detect fake accounts mimicking the organization.",
            "Monitor data exfiltration trends through social media or unauthorized communication apps."
        ],
        "apt": [
            "TELCO BPO Campaign"
        ],
        "spl_query": [
            'index=proxy_logs OR index=firewall_logs\n| search dest_domain="linkedin.com" OR dest_domain="facebook.com" OR dest_domain="gmail.com"\n| stats count by user, dest_domain, uri_path'
        ],
        "hunt_steps": [
            "Search for unusual user access to personal webmail or social media platforms from corporate assets.",
            "Analyze device usage patterns for unexpected communication behavior.",
            "Correlate URL visits with known phishing infrastructure (Bit.ly links, fake domains)."
        ],
        "expected_outcomes": [
            "Detection of social media-based or webmail-based phishing messages.",
            "Identification of users communicating with adversary-controlled personas."
        ],
        "false_positive": "Legitimate recruitment or professional outreach via social platforms may resemble phishing. Confirm source authenticity before action.",
        "clearing_steps": [
            "Alert the impersonated user or department to update public warnings.",
            "Notify platform support teams to take down fake profiles.",
            "Educate involved users on identifying social engineering behavior."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1566", "example": "Adversary later sends malicious link or attachment after gaining trust"}
        ],
        "watchlist": [
            "Employees engaging with unsolicited recruitment messages",
            "Profiles with similar names/pictures to legitimate corporate users",
            "Outbound traffic to uncommon messaging platforms"
        ],
        "enhancements": [
            "Deploy digital risk protection to monitor impersonation attempts.",
            "Establish relationships with platform security teams for rapid takedown.",
            "Use browser plugins that alert users about potential impersonation risks."
        ],
        "summary": "Spearphishing via third-party services like social media and personal email allows attackers to bypass corporate defenses and build rapport with victims in a familiar context. These attacks often involve job offers or technical support impersonation, tricking users into revealing internal details.",
        "remediation": "Investigate the scope of data shared, report abuse to platforms, and conduct a security refresher for affected individuals.",
        "improvements": "Enhance digital footprint monitoring, limit what employees publicly share, and simulate spearphishing campaigns through social platforms.",
        "mitre_version": "16.1"
    }
