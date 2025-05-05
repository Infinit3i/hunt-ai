def get_content():
    return {
        "id": "G0083",
        "url_id": "SilverTerrier",
        "title": "SilverTerrier",
        "tags": ["Nigeria", "BEC", "financial theft", "phishing", "education sector", "malware"],
        "description": (
            "SilverTerrier is a Nigerian threat actor active since 2014 that primarily targets organizations in the high technology, "
            "higher education, and manufacturing sectors. The group is known for large-scale Business Email Compromise (BEC) operations, "
            "often leveraging commodity malware like Agent Tesla, Lokibot, and NanoCore. They exploit email-based lures and exfiltrate "
            "financial or personal data using commonly abused communication protocols like HTTP, FTP, and SMTP."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1071.001", "T1071.002", "T1071.003", "T1657"
        ],
        "contributors": [],
        "version": "1.2",
        "created": "29 January 2019",
        "last_modified": "27 September 2023",
        "navigator": "",
        "references": [
            {"source": "Unit42", "url": "https://unit42.paloaltonetworks.com/silverterrier-the-rise-of-nigerian-business-email-compromise/"},
            {"source": "Unit42", "url": "https://unit42.paloaltonetworks.com/silverterrier-the-next-evolution-in-nigerian-cybercrime/"}
        ],
        "resources": [],
        "remediation": (
            "Implement email filtering with attachment scanning and domain reputation analysis. "
            "Use DMARC, SPF, and DKIM to prevent spoofing. Conduct user awareness training focused on phishing and business email compromise."
        ),
        "improvements": (
            "Enforce strict financial workflows requiring voice confirmation for fund transfers. "
            "Deploy EDR solutions to detect commodity malware families like Lokibot and Agent Tesla. "
            "Monitor outbound FTP, SMTP, and HTTP traffic for unusual destinations."
        ),
        "hunt_steps": [
            "Search for outbound connections over FTP or SMTP to uncommon domains.",
            "Inspect mailboxes for suspicious login patterns or rule creation events.",
            "Scan endpoints for known IOCs from commodity RATs (e.g., Agent Tesla, NanoCore)."
        ],
        "expected_outcomes": [
            "Detection of credential harvesting and data exfiltration via RATs.",
            "Identification of compromised accounts used in BEC.",
            "Disruption of malware C2 communications via network monitoring."
        ],
        "false_positive": "Legitimate applications may use FTP or SMTP protocols; validate domains and context to confirm malicious behavior.",
        "clearing_steps": [
            "Block C2 domains/IPs associated with Agent Tesla, Lokibot, NanoCore, and other known SilverTerrier malware.",
            "Reset credentials of compromised accounts and review financial transaction history.",
            "Reimage systems where malware is detected to ensure full cleanup."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://unit42.paloaltonetworks.com/silverterrier-the-rise-of-nigerian-business-email-compromise/",
                "https://unit42.paloaltonetworks.com/silverterrier-the-next-evolution-in-nigerian-cybercrime/"
            ]
        }
    }
