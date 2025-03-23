def get_content():
    return {
        "id": "T1585.001",
        "url_id": "T1585/001",
        "title": "Establish Accounts: Social Media Accounts",
        "description": "Adversaries may create and cultivate social media accounts that can be used during targeting. Adversaries can use social media to build a persona that furthers operations through public presence, history, and affiliations.",
        "tags": ["persona", "social engineering", "resource development"],
        "tactic": "Resource Development",
        "protocol": "",
        "os": "PRE",
        "tips": [
            "Monitor for fake accounts claiming association with your organization",
            "Use threat intel services to track adversary-created personas",
            "Educate users about suspicious social media behavior"
        ],
        "data_sources": "Network Traffic: Network Traffic Content, Persona: Social Media",
        "log_sources": [
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Persona", "source": "", "destination": "Social Media"}
        ],
        "source_artifacts": [
            {"type": "Persona Profile", "location": "Social Media Platforms", "identify": "New accounts with recent creation date and high outreach"}
        ],
        "destination_artifacts": [
            {"type": "Connection Requests", "location": "Target User Profiles", "identify": "Multiple requests to employees in the same organization"}
        ],
        "detection_methods": [
            "Account age and profile completeness analysis",
            "Detection of outreach spikes from new social media accounts",
            "Behavioral monitoring of connection/request patterns"
        ],
        "apt": [],
        "spl_query": [],
        "hunt_steps": [
            "Search for social accounts using organization branding",
            "Review open-source indicators of suspicious connections or personas",
            "Engage threat intel feeds to correlate social media personas"
        ],
        "expected_outcomes": [
            "Identification of adversary-created social media accounts",
            "Early detection of social engineering campaigns"
        ],
        "false_positive": "New legitimate employees creating accounts or updating job status may appear suspicious without context.",
        "clearing_steps": [
            "Report fake accounts to social media platforms",
            "Notify affected users of impersonation risks",
            "Update security awareness training"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1566/003", "example": "Spearphishing through social media messages"}
        ],
        "watchlist": [
            "Fake accounts mimicking employees",
            "Unusual social engagement from recently created accounts"
        ],
        "enhancements": [
            "Automate scanning of LinkedIn, Facebook, Twitter, etc., for impersonation patterns",
            "Use image recognition to detect reused photos across multiple personas"
        ],
        "summary": "Adversaries may establish social media accounts to create credible personas used in operations like social engineering and spearphishing.",
        "remediation": "Enforce branding policy, monitor impersonation attempts, and establish takedown procedures with social platforms.",
        "improvements": "Integrate identity protection solutions with HR to monitor impersonation threats automatically.",
        "mitre_version": "16.1"
    }
