def get_content():
    return {
        "id": "G1020",
        "url_id": "Mustard_Tempest",
        "title": "Mustard Tempest",
        "tags": ["initial-access-broker", "SocGholish", "malvertising", "drive-by", "partnered-with-Indrik-Spider"],
        "description": (
            "Mustard Tempest is an initial access broker operating the SocGholish distribution network since at least 2017. "
            "They partner with groups like Indrik Spider to distribute additional malware including LockBit, WastedLocker, and RATs. "
            "They are known for leveraging malvertising, drive-by downloads, and fake browser updates for initial access."
        ),
        "associated_groups": ["DEV-0206", "TA569", "GOLD PRELUDE", "UNC1543"],
        "campaigns": [],
        "techniques": [
            "T1583.004", "T1583.008", "T1584.001", "T1189", "T1105", "T1036.005", "T1566.002",
            "T1608.001", "T1608.004", "T1608.006", "T1082", "T1204.001"
        ],
        "contributors": [],
        "version": "1.0",
        "created": "06 December 2023",
        "last_modified": "25 March 2024",
        "navigator": "",
        "references": [
            {"source": "Microsoft", "url": "https://www.microsoft.com/security/blog/2022/05/09/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/security/blog/2023/07/12/how-microsoft-names-threat-actors"},
            {"source": "Secureworks", "url": "https://www.secureworks.com/research/gold-prelude"},
            {"source": "Andrew Northern", "url": "https://www.redcanary.com/blog/socgholish-fake-update-threat/"},
            {"source": "Milenkoski, A.", "url": "https://www.redcanary.com/blog/socgholish-diversifies-malware-staging/"},
            {"source": "Red Canary", "url": "https://www.redcanary.com/resources/reports/2024-threat-detection-report/"}
        ],
        "resources": [],
        "remediation": (
            "Block and monitor domains used in fake update campaigns. "
            "Implement endpoint protection capable of detecting JavaScript-based malware. "
            "Restrict web traffic and enforce strong URL filtering policies. "
            "Conduct regular user awareness training to reduce phishing risks."
        ),
        "improvements": (
            "Enhance monitoring of ad-based redirections and SEO poisoning attempts. "
            "Deploy behavior-based detections for drive-by downloads and anomalous browser-based JavaScript execution."
        ),
        "hunt_steps": [
            "Search for unusual JavaScript execution in browser cache locations.",
            "Look for filenames containing homoglyphs (e.g., Cyrillic characters) in update-related downloads.",
            "Identify drive-by infections tied to fake browser updates in web proxy logs."
        ],
        "expected_outcomes": [
            "Detection of unauthorized drive-by infections.",
            "Isolation of systems compromised via fake browser updates.",
            "Attribution of early-stage infections to SocGholish infrastructure."
        ],
        "false_positive": (
            "Legitimate browser update processes may use similar file names but not homoglyphs. "
            "Care must be taken when flagging update downloads to avoid user disruption."
        ),
        "clearing_steps": [
            "Delete all downloaded files related to fake browser updates.",
            "Re-image compromised systems if Cobalt Strike or persistent malware is found.",
            "Revoke any credentials stolen during initial compromise."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
