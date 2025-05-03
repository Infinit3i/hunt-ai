def get_content():
    return {
        "id": "G0077",
        "url_id": "Leafminer",
        "title": "Leafminer",
        "tags": ["iranian", "middle-east", "government targeting", "credential theft"],
        "description": (
            "Leafminer is an Iranian threat group that has been active since at least early 2017. It primarily targets "
            "government and business entities in the Middle East. Leafminer has leveraged a wide range of open-source "
            "and publicly available tools in its operations, utilizing watering hole attacks, credential theft, remote access tools, "
            "and process injection techniques. The group has employed a combination of custom and commodity malware and has demonstrated "
            "a strong focus on acquiring credentials and collecting email and file-based intelligence from victim systems."
        ),
        "associated_groups": ["Raspite"],
        "campaigns": [],
        "techniques": [
            "T1110.003", "T1059.007", "T1136.001", "T1555", "T1555.003", "T1189", "T1114.002", "T1083", "T1046", "T1027.010",
            "T1588.002", "T1003.001", "T1003.004", "T1003.005", "T1055.013", "T1018", "T1552.001"
        ],
        "contributors": [],
        "version": "2.4",
        "created": "17 October 2018",
        "last_modified": "16 April 2025",
        "navigator": "https://attack.mitre.org/groups/G0077/",
        "references": [
            {"source": "Symantec Security Response", "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/leafminer-espionage-middle-east"},
            {"source": "Dragos", "url": "https://www.dragos.com/blog/industry-news/raspite-overlapping-infrastructure-targeting-middle-east/"}
        ],
        "resources": [
            "https://attack.mitre.org/groups/G0077/",
            "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/leafminer-espionage-middle-east"
        ],
        "remediation": (
            "Apply regular security patches, monitor access to email systems and shared file storage, and restrict execution of known credential dumping tools. "
            "Monitor for obfuscated script execution and unauthorized account creation activity."
        ),
        "improvements": (
            "Deploy advanced behavioral analytics to detect anomalous access patterns and use of dual-purpose tools like MailSniper and LaZagne. "
            "Enhance phishing protection at the gateway and implement DNS filtering for known C2 infrastructure."
        ),
        "hunt_steps": [
            "Look for use of tools like LaZagne, Mimikatz, PsExec, and MailSniper on endpoints",
            "Audit registry and file system for presence of obfuscated JavaScript files",
            "Monitor LSASS memory access events from unauthorized or unsigned binaries",
            "Check Exchange logs for abnormal remote mailbox searches"
        ],
        "expected_outcomes": [
            "Early detection of credential theft and unauthorized mailbox access",
            "Identification of obfuscated script artifacts in user directories",
            "Prevention of lateral movement using discovered credentials"
        ],
        "false_positive": (
            "Sysinternals tools, PsExec, and MailSniper may be used legitimately by administrators. Review execution context, origin, and command-line parameters."
        ),
        "clearing_steps": [
            "Remove unauthorized local accounts and reset associated credentials",
            "Clear malware persistence via autorun or scheduled task registry entries",
            "Purge staged credential logs and secure LSASS memory space",
            "Patch Exchange server vulnerabilities and revoke exposed tokens"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/leafminer-espionage-middle-east",
                "https://attack.mitre.org/groups/G0077/"
            ]
        }
    }
