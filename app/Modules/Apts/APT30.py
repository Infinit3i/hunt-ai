def get_content():
    return {
        "id": "G0013",
        "url_id": "apt30",
        "title": "APT30",
        "tags": ["Chinese", "espionage"],
        "description": "APT30 is a threat group suspected to be associated with the Chinese government. While Naikon shares some characteristics with APT30, the two groups do not appear to be exact matches.",
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1566.001",  # Phishing: Spearphishing Attachment
            "T1204.002"   # User Execution: Malicious File
        ],
        "contributors": [],
        "version": "1.1",
        "created": "31 May 2017",
        "last_modified": "17 November 2024",
        "navigator": "https://attack.mitre.org/groups/G0013/",
        "references": [
            {"source": "FireEye", "url": "https://www.fireeye.com/content/dam/fireeye-www/current-threats/pdfs/rpt-apt30.pdf"},
            {"source": "Kaspersky", "url": "https://securelist.com/the-naikon-apt/69731/"}
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
