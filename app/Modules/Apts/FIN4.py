def get_content():
    return {
        "id": "G0085",
        "url_id": "FIN4",
        "title": "FIN4",
        "tags": ["financial", "spearphishing", "credential access"],
        "description": "FIN4 is a financially-motivated threat group that has targeted confidential information related to the public financial market, particularly in healthcare and pharmaceutical sectors, since at least 2013. The group primarily focuses on capturing credentials for email and other sensitive communications rather than deploying persistent malware.",
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1071.001", "T1059.005", "T1114.002", "T1564.008", 
            "T1056.001", "T1056.002", "T1566.001", "T1566.002", 
            "T1090.003", "T1204.001", "T1204.002", "T1078"
        ],
        "contributors": [],
        "version": "1.2",
        "created": "31 January 2019",
        "last_modified": "17 November 2024",
        "navigator": "",
        "references": [
            {"source": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/2014/12/hacking-the-street-fin4.html"},
            {"source": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/2014/11/fin4-stealing-insider-info.html"},
            {"source": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/2014/12/hacking-the-street-fin4.html"}
        ],
        "resources": [],
        "remediation": "Implement MFA across all externally accessible systems, especially email. Monitor for suspicious email rules and block the use of Tor where possible.",
        "improvements": "Enhance detection for credential phishing attempts and suspicious Outlook rule creation. Regularly audit email accounts for unauthorized access.",
        "hunt_steps": [
            "Search for Outlook rules deleting messages with keywords like 'hacked', 'phish', 'malware'.",
            "Monitor login attempts from Tor exit nodes.",
            "Inspect email metadata for signs of compromised internal accounts sending phishing messages."
        ],
        "expected_outcomes": [
            "Identification of unauthorized rule creation in email systems.",
            "Detection of unusual login patterns or locations.",
            "Discovery of internal accounts sending unexpected attachments or links."
        ],
        "false_positive": "Legitimate use of Outlook rules or Tor for privacy may result in false positives.",
        "clearing_steps": [
            "Revoke compromised credentials.",
            "Delete unauthorized Outlook rules.",
            "Conduct a full email account audit and notify affected parties."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
