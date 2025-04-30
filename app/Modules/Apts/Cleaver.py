def get_content():
    return {
        "id": "G0003",
        "url_id": "Cleaver",
        "title": "Cleaver",
        "tags": [
            "iran-based",
            "operation-cleaver",
            "credential-dumping",
            "social-engineering",
            "custom-malware"
        ],
        "description": "Cleaver is a threat group attributed to Iranian actors, known for Operation Cleaver. Their operations include ARP cache poisoning, credential dumping, and custom tool development. Circumstantial evidence links them to Threat Group 2889 (TG-2889).",
        "associated_groups": ["Threat Group 2889", "TG-2889"],
        "campaigns": [],
        "techniques": [
            "T1557.002", "T1587.001", "T1585.001", "T1588.002", "T1003.001"
        ],
        "contributors": [],
        "version": "1.3",
        "created": "31 May 2017",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "Cylance",
                "url": "https://www.cylance.com/content/dam/cylance/pdfs/reports/operation-cleaver-report.pdf"
            },
            {
                "source": "Dell SecureWorks",
                "url": "https://www.secureworks.com/research/suspected-iran-based-hacker-group-creates-network-of-fake-linkedin-profiles"
            }
        ],
        "resources": [],
        "remediation": "",
        "improvements": "",
        "hunt_steps": [],
        "expected_outcomes": [],
        "false_positive": "",
        "clearing_steps": [],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }