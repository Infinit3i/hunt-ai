def get_content():
    return {
        "id": "G1033",
        "url_id": "Star_Blizzard",
        "title": "Star Blizzard",
        "tags": ["Russia", "phishing", "credential theft", "espionage", "EvilGinx", "Spica", "NATO targets"],
        "description": (
            "Star Blizzard is a Russian cyber espionage and influence group active since at least 2019, targeting academic, defense, "
            "government, NGO, and think tank entities—particularly in NATO countries like the US and UK. The group has been linked with "
            "persistent credential theft and spearphishing campaigns, often leveraging tools such as EvilGinx and malware like Spica. "
            "Their activity aligns with Russian state interests and includes advanced evasion techniques such as session hijacking to bypass MFA."
        ),
        "associated_groups": ["SEABORGIUM", "Callisto Group", "TA446", "COLDRIVER"],
        "campaigns": [],
        "techniques": [
            "T1583", "T1583.001", "T1059.007", "T1586.002", "T1114.002", "T1114.003",
            "T1585.001", "T1585.002", "T1589", "T1588.002", "T1566.001", "T1598.002", "T1598.003",
            "T1593", "T1608.001", "T1539", "T1550.004", "T1204.002", "T1078"
        ],
        "contributors": ["Aung Kyaw Min Naing", "@Nolan"],
        "version": "1.0",
        "created": "14 June 2024",
        "last_modified": "14 June 2024",
        "navigator": "",
        "references": [
            {"source": "Microsoft Threat Intelligence", "url": "https://www.microsoft.com/en-us/security/blog/2022/08/15/disrupting-seaborgiums-ongoing-phishing-operations"},
            {"source": "CISA", "url": "https://www.cisa.gov/news-events/alerts/2023/12/07/russian-fsb-cyber-actor-star-blizzard-continues-worldwide-spear-phishing-campaigns"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/en-us/security/blog/2023/12/07/star-blizzard-increases-sophistication-and-evasion-in-ongoing-attacks"},
            {"source": "Shields, W.", "url": "https://www.malware.news/t/russian-threat-group-coldriver-expands-its-targeting-of-western-officials-to-include-the-use-of-malware/72656"}
        ],
        "resources": [],
        "remediation": (
            "Apply conditional access and location-based MFA enforcement to sensitive accounts. "
            "Inspect forwarding rules on high-risk users. Regularly audit cloud identity activity logs for cookie theft or suspicious login patterns."
        ),
        "improvements": (
            "Deploy phishing-resistant MFA like FIDO2 hardware tokens. Enhance user awareness around social engineering "
            "from spoofed academic or think tank entities. Block or sandbox links to unknown cloud storage in inbound messages."
        ),
        "hunt_steps": [
            "Search logs for `Set-Mailbox -ForwardingSmtpAddress` or changes to inbox rules.",
            "Look for EvilGinx-like domains in proxy or DNS logs tied to targets using MFA.",
            "Flag JavaScript redirects leading to session cookie theft or unusual login locations using the same user-agent/session."
        ],
        "expected_outcomes": [
            "Detection of MFA bypass via session cookie reuse.",
            "Identification of targeted credential harvesting campaigns using social engineering.",
            "Visibility into email exfiltration via forwarding rules or direct access."
        ],
        "false_positive": "Legitimate cloud services or forwarding rules may resemble adversary behavior; context and timing are key for analysis.",
        "clearing_steps": [
            "Revoke and reissue session cookies for impacted accounts.",
            "Delete malicious forwarding rules and impersonation accounts.",
            "Harden phishing protections in mail gateways and disable legacy authentication."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://www.microsoft.com/en-us/security/blog/2023/12/07/star-blizzard-increases-sophistication-and-evasion-in-ongoing-attacks"
            ]
        }
    }
