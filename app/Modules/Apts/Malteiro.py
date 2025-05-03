def get_content():
    return {
        "id": "G1026",
        "url_id": "Malteiro",
        "title": "Malteiro",
        "tags": ["financially motivated", "Latin America", "MaaS", "banking trojan"],
        "description": "Malteiro is a financially motivated criminal group, believed to be based in Brazil, and has been active since at least November 2019. The group operates the Mispadu banking trojan under a Malware-as-a-Service model, primarily targeting victims in Latin America—especially Mexico—and Europe, notably Spain and Portugal.",
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1059.005", "T1555", "T1555.003", "T1140", "T1657", "T1027.013",
            "T1566.001", "T1055.001", "T1518.001", "T1082", "T1614.001", "T1204.002"
        ],
        "contributors": ["Daniel Fernando Soriano Espinosa", "SCILabs"],
        "version": "1.0",
        "created": "13 March 2024",
        "last_modified": "29 March 2024",
        "navigator": "",  # You may link to MITRE Navigator layer if available
        "references": [
            {"source": "SCILabs", "url": "https://scilabs.io/threat-profile-malteiro"},
            {"source": "SCILabs", "url": "https://scilabs.io/ursa-mispadu-overlap"}
        ],
        "resources": [
            "https://attack.mitre.org/groups/G1026/",
            "https://scilabs.io/threat-profile-malteiro",
            "https://scilabs.io/ursa-mispadu-overlap"
        ],
        "remediation": "Educate users about phishing risks, block execution of VBS scripts from email sources, monitor and restrict DLL injection, and implement mail and web content filtering to reduce malicious delivery vectors.",
        "improvements": "Deploy behavioral monitoring to detect process injection patterns, enhance email gateway inspection for encoded content, and implement endpoint protection to detect Mispadu’s known indicators.",
        "hunt_steps": [
            "Search for DLL injection behavior from unknown parent processes",
            "Monitor for encoded VBS execution patterns via Base64",
            "Review registry run key modifications linked to new persistence mechanisms",
            "Look for NirSoft utility executions (MailPassView, WebBrowserPassView)"
        ],
        "expected_outcomes": [
            "Detection of credential harvesting via known NirSoft tools",
            "Identification of Mispadu-related persistence mechanisms",
            "Alerts on spearphishing attachments containing obfuscated content",
            "Recognition of language-based evasion behavior"
        ],
        "false_positive": "Use of NirSoft tools in legitimate forensic settings may trigger alerts. Validate intent and user context before responding.",
        "clearing_steps": [
            "Remove any malicious registry entries created for persistence",
            "Clear temporary directories for potential dropper files",
            "Reset credentials stored in web browsers and mail clients",
            "Conduct full scan for injected DLLs and remove Mispadu binaries"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://scilabs.io/threat-profile-malteiro",
                "https://scilabs.io/ursa-mispadu-overlap"
            ]
        }
    }
