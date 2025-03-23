def get_content():
    return {
        "id": "T1585",
        "url_id": "T1585",
        "title": "Establish Accounts",
        "description": "Adversaries may create and cultivate accounts with services that can be used during targeting. Adversaries can create accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations.",
        "tags": ["persona", "impersonation", "social engineering", "phishing", "account creation"],
        "tactic": "Resource Development",
        "protocol": "",
        "os": "PRE",
        "tips": [
            "Monitor for new social media accounts claiming affiliation with your organization.",
            "Be cautious of excessive connection requests or outreach from newly created profiles.",
            "Flag use of free trials for infrastructure registration tied to suspicious activity."
        ],
        "data_sources": "Network Traffic: Network Traffic Content, Persona: Social Media",
        "log_sources": [
            {"type": "Persona", "source": "Social Media", "destination": "Threat Intelligence Platform"},
            {"type": "Network Traffic", "source": "Endpoint", "destination": "Firewall/Proxy"}
        ],
        "source_artifacts": [
            {"type": "Account Creation", "location": "Public Platform", "identify": "Fake personas or newly registered emails"}
        ],
        "destination_artifacts": [
            {"type": "Connection Requests", "location": "Target's Social Media", "identify": "Multiple connection requests from newly created personas"}
        ],
        "detection_methods": [
            "Monitor social media mentions and job title claims",
            "Correlate registration timestamps with bursts of activity",
            "Track public account registration via OSINT platforms"
        ],
        "apt": [],
        "spl_query": [
            'index=osint_social_media "persona" OR "fake account"\n| stats count by platform, username, first_seen'
        ],
        "hunt_steps": [
            "Scan for social media profiles that mention your company name",
            "Investigate newly registered domains tied to email services",
            "Search GitHub, Docker Hub, and other platforms for impersonation accounts"
        ],
        "expected_outcomes": [
            "Discovery of adversary-built persona networks",
            "Detection of phishing infrastructure registration"
        ],
        "false_positive": "Legitimate marketing, recruiting, or partnership outreach from new accounts may resemble this activity.",
        "clearing_steps": [
            "Report impersonating accounts to the respective platforms",
            "Revoke any services accessed using fraudulent accounts",
            "Alert users targeted by those accounts"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1566", "example": "Phishing using newly created accounts"},
            {"tactic": "Resource Development", "technique": "T1583", "example": "Infrastructure registered via fake identity"}
        ],
        "watchlist": [
            "Recently created social media profiles claiming employment",
            "Burst activity from free/trial cloud accounts"
        ],
        "enhancements": [
            "Integrate threat intel feeds with persona watchlists",
            "Apply ML to detect account creation patterns mimicking real employees"
        ],
        "summary": "Establishing accounts is a precursor step used by adversaries to develop online personas, stage phishing, or register infrastructure covertly.",
        "remediation": "Engage with social platforms to remove fake accounts, raise awareness internally about impersonation risks.",
        "improvements": "Partner with social media and cloud providers for rapid takedown APIs. Use honeypot accounts to detect persona recon.",
        "mitre_version": "16.1"
    }
