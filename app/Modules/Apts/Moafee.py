def get_content():
    return {
        "id": "G0002",
        "url_id": "Moafee",
        "title": "Moafee",
        "tags": ["Chinese APT", "Guangdong", "DragonOK affiliation", "espionage"],
        "description": "Moafee is a suspected China-based cyber espionage group believed to operate from Guangdong Province. It has shown overlaps in tactics, techniques, and procedures with DragonOK, including the use of similar custom tools. Moafee’s known capabilities are limited but notable for their use of binary padding in malware obfuscation.",
        "associated_groups": ["DragonOK"],
        "campaigns": [],
        "techniques": [
            "T1027.001"
        ],
        "contributors": [],
        "version": "1.1",
        "created": "31 May 2017",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "FireEye Blog",
                "url": "https://www.fireeye.com/blog/threat-research/2014/09/the-path-to-mass-producing-cyber-attacks.html"
            }
        ],
        "resources": [
            "https://attack.mitre.org/groups/G0002/"
        ],
        "remediation": "Identify and block executables exhibiting excessive binary padding. Employ antivirus and EDR tools capable of detecting obfuscation techniques. Review inbound malware for padding anomalies.",
        "improvements": "Enhance file scanning capabilities with entropy-based detection of padded binaries. Update YARA rules to catch binary obfuscation patterns common in Moafee campaigns.",
        "hunt_steps": [
            "Search for binary files with large blocks of null bytes or repeating patterns near the end of the file",
            "Check for known PoisonIvy indicators",
            "Monitor for execution of heavily padded binaries with low entropy",
            "Validate use of registry keys commonly modified by PoisonIvy"
        ],
        "expected_outcomes": [
            "Detection of obfuscated malware samples using binary padding",
            "Correlation of activity with DragonOK-linked tools such as PoisonIvy",
            "Visibility into persistence mechanisms involving Registry Run keys"
        ],
        "false_positive": "Some legitimate installers or applications may include padding for alignment or packaging purposes. Use contextual indicators to distinguish malicious binaries.",
        "clearing_steps": [
            "Remove PoisonIvy implants and registry persistence keys",
            "Clean up any suspicious executables using padding-based obfuscation",
            "Audit systems for rootkit artifacts and dynamic link library injections"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://www.fireeye.com/blog/threat-research/2014/09/the-path-to-mass-producing-cyber-attacks.html"
            ]
        }
    }
