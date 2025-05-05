def get_content():
    return {
        "id": "G1015",
        "url_id": "Scattered_Spider",
        "title": "Scattered Spider",
        "tags": ["cybercriminal", "ransomware", "social engineering", "multi-sector"],
        "description": (
            "Scattered Spider is a native English-speaking cybercriminal group active since at least 2022. "
            "Initially targeting CRM and BPO firms, the group expanded in 2023 to include victims across gaming, hospitality, retail, managed service providers (MSPs), manufacturing, and finance. "
            "They are known for sophisticated social engineering, bypassing endpoint defenses, and deploying ransomware such as BlackCat. Their operations involve credential phishing, SIM swapping, cloud abuse, and malware deployment."
        ),
        "associated_groups": ["Roasted 0ktapus", "Octo Tempest", "Storm-0875"],
        "campaigns": [
            {
                "id": "C0027",
                "name": "C0027",
                "first_seen": "June 2022",
                "last_seen": "December 2022",
                "references": [
                    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a",
                    "https://www.crowdstrike.com/blog/not-a-simulation-intrusion-campaign-targeting-telco-and-bpo-companies",
                    "https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction"
                ]
            }
        ],
        "techniques": [
            "T1087.002", "T1087.003", "T1087.004", "T1098.001", "T1098.003", "T1098.005", "T1217", "T1580",
            "T1538", "T1136", "T1486", "T1530", "T1213.002", "T1213.003", "T1213.005", "T1074", "T1006",
            "T1484.002", "T1114", "T1567.002", "T1190", "T1068", "T1133", "T1083", "T1657", "T1589.001",
            "T1564.008", "T1656", "T1105", "T1556.006", "T1556.009", "T1578.002", "T1621", "T1046", "T1588.002",
            "T1003.003", "T1003.006", "T1069.003", "T1566.004", "T1598", "T1598.001", "T1598.004", "T1572",
            "T1090", "T1219", "T1021.007", "T1018", "T1539", "T1553.002", "T1552.001", "T1552.004", "T1204",
            "T1078.004", "T1102", "T1047", "T1660", "T1451"
        ],
        "contributors": [],
        "version": "2.0",
        "created": "05 July 2023",
        "last_modified": "04 April 2024",
        "navigator": "",
        "references": [
            {"source": "CrowdStrike", "url": "https://www.crowdstrike.com/blog/scattered-spider-exploits-windows-deficiencies"},
            {"source": "CISA", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries"}
        ],
        "resources": [],
        "remediation": (
            "Enforce strict MFA controls including number matching and device binding. "
            "Implement Zero Trust principles with strict identity verification. "
            "Monitor for excessive MFA requests, suspicious login patterns, and SIM swaps."
        ),
        "improvements": (
            "Improve cloud monitoring with behavior-based analytics. "
            "Regularly audit conditional access policies. "
            "Block the use of personal devices in sensitive environments unless properly secured and monitored."
        ),
        "hunt_steps": [
            "Search authentication logs for signs of MFA fatigue attacks.",
            "Identify usage of remote tools like AnyDesk, LogMeIn, and ConnectWise.",
            "Scan cloud activity for unauthorized instance creations or unusual role assignments."
        ],
        "expected_outcomes": [
            "Detection of social engineering-based initial access.",
            "Identification of lateral movement within cloud and hybrid environments.",
            "Capture of exfiltration patterns to MEGA or other file-sharing platforms."
        ],
        "false_positive": "Some cloud resource creation or MFA usage may be legitimate; verify context with IT operations and identity logs.",
        "clearing_steps": [
            "Reset credentials and revoke tokens for affected accounts.",
            "Remove unauthorized MFA registrations and conditional access modifications.",
            "Conduct forensic review of cloud assets and communication logs."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://www.trellix.com/en-us/about/newsroom/stories/research/scattered-spider-the-modus-operandi.html"
            ]
        }
    }
