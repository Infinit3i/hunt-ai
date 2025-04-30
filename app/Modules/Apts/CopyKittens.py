def get_content():
    return {
        "id": "G0052",
        "url_id": "CopyKittens",
        "title": "CopyKittens",
        "tags": ["cyber-espionage", "Iran", "Operation Wilted Tulip", "APT", "Middle East"],
        "description": "CopyKittens is an Iranian cyber espionage group active since at least 2013. The group has primarily targeted countries such as Israel, Saudi Arabia, Turkey, the United States, Jordan, and Germany. It is best known for the Operation Wilted Tulip campaign and is noted for using a combination of custom tools and known frameworks like Empire and Metasploit.",
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1560.001", "T1560.003", "T1059.001", "T1564.003",
            "T1588.002", "T1090", "T1553.002", "T1218.011"
        ],
        "contributors": [],
        "version": "1.6",
        "created": "16 January 2018",
        "last_modified": "17 November 2024",
        "navigator": "",  # Add link to MITRE Navigator layer if applicable
        "references": [
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0052/"},
            {"source": "ClearSky Cyber Security", "url": "https://www.clearskysec.com/copykitten/"},
            {"source": "Trend Micro", "url": "https://documents.trendmicro.com/assets/wp/wp-operation-wilted-tulip.pdf"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/security/blog/2022/06/02/exposing-polonium-activity-and-infrastructure-targeting-israeli-organizations/"}
        ],
        "resources": [],
        "remediation": "Implement controls to detect and block PowerShell-based payloads and suspicious rundll32 execution. Review certificate validation policies to guard against trust control subversion. Monitor use of VPN tunneling tools like AirVPN on enterprise endpoints.",
        "improvements": "Enhance detection capabilities for script-based payloads, implement stricter code signing validation, and improve visibility into ZIP archive generation and unusual proxy traffic.",
        "hunt_steps": [
            "Hunt for rundll32.exe loading shellcode or unfamiliar DLLs.",
            "Look for command-line parameters indicating hidden PowerShell windows (e.g., -w hidden).",
            "Search for tools known to be used by CopyKittens like ZPP or Empire payloads.",
            "Review logs for outbound VPN/proxy traffic indicative of AirVPN use."
        ],
        "expected_outcomes": [
            "Identification of post-exploitation tools like Empire or Metasploit.",
            "Detection of unauthorized ZIP or encrypted archive creation.",
            "Blocking of C2 channels via known proxy services.",
            "Reinforced endpoint control over PowerShell and signed binaries."
        ],
        "false_positive": "Legitimate administrative use of rundll32.exe and PowerShell may overlap. Correlate behavior with execution context, parent processes, and origin network zones.",
        "clearing_steps": [
            "Remove malicious registry keys or scheduled tasks related to persistence.",
            "Terminate unauthorized or anomalous rundll32 and PowerShell processes.",
            "Revoke and reissue compromised certificates where trust control subversion is confirmed.",
            "Purge VPN software and block its reinstallation via group policy."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://attack.mitre.org/groups/G0052/",
                "https://documents.trendmicro.com/assets/wp/wp-operation-wilted-tulip.pdf"
            ]
        }
    }
