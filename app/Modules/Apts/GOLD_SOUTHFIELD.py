def get_content():
    return {
        "id": "G0115",
        "url_id": "GOLD_SOUTHFIELD",
        "title": "GOLD SOUTHFIELD",
        "tags": ["financial", "ransomware", "RaaS", "REvil", "Pinchy Spider", "supply-chain"],
        "description": "GOLD SOUTHFIELD is a financially motivated threat group known for operating the REvil Ransomware-as-a-Service (RaaS). Active since at least 2018, the group provides backend infrastructure and technical support to affiliates who deploy REvil. GOLD SOUTHFIELD is notable for pioneering the double extortion tactic, stealing sensitive data and threatening to leak it publicly unless ransom demands are met.",
        "associated_groups": ["Pinchy Spider"],
        "campaigns": [],
        "techniques": [
            "T1059.001",  # PowerShell
            "T1190",      # Exploit Public-Facing Application
            "T1133",      # External Remote Services
            "T1027.010",  # Command Obfuscation
            "T1566",      # Phishing
            "T1219",      # Remote Access Tools
            "T1113",      # Screen Capture
            "T1195.002",  # Compromise Software Supply Chain
            "T1199"       # Trusted Relationship
        ],
        "contributors": ["Thijn Bukkems", "Amazon"],
        "version": "2.0",
        "created": "22 September 2020",
        "last_modified": "16 April 2025",
        "navigator": "",  # Add ATT&CK Navigator link if available
        "references": [
            {
                "source": "Counter Threat Unit Research Team",
                "url": "https://www.secureworks.com/research/revil-sodinokibi-ransomware"
            },
            {
                "source": "Secureworks",
                "url": "https://www.secureworks.com/research/revil-the-gandcrab-connection"
            },
            {
                "source": "Tetra Defense",
                "url": "https://www.tetradefense.com/resources/sodinokibi-analysis/"
            },
            {
                "source": "Adam Meyers",
                "url": "https://www.crowdstrike.com/blog/the-evolution-of-pinchy-spider-from-gandcrab-to-revil/"
            }
        ],
        "resources": [],
        "remediation": "Block known REvil IOCs and monitor for abnormal use of remote management tools. Disable macros and restrict PowerShell use via GPO. Audit and harden MSP and RMM configurations.",
        "improvements": "Detect encoded PowerShell commands and obfuscation patterns. Apply strict egress filtering to prevent data exfiltration. Monitor for signs of software supply chain compromise.",
        "hunt_steps": [
            "Look for base64-encoded PowerShell script execution.",
            "Identify unauthorized use of ConnectWise Control or similar RMM tools.",
            "Analyze traffic to known REvil C2 infrastructure and web compromises.",
            "Check for signs of stolen data staging or ransom note delivery."
        ],
        "expected_outcomes": [
            "Identification of early-stage REvil deployment.",
            "Detection of phishing-based initial access vectors.",
            "Prevention of data exfiltration and public leak extortion attempts."
        ],
        "false_positive": "Legitimate IT operations may use ConnectWise or PowerShell. Validate through behavioral context and time-of-use indicators.",
        "clearing_steps": [
            "Terminate RMM sessions and remove unauthorized tools.",
            "Restore affected systems from clean backups.",
            "Patch exploited vulnerabilities in WebLogic or other services.",
            "Revoke and reset credentials used during the compromise."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
