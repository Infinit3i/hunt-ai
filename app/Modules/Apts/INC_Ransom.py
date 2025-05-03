def get_content():
    return {
        "id": "G1032",
        "url_id": "INC_Ransom",
        "title": "INC Ransom",
        "tags": ["ransomware", "extortion", "data theft", "financially-motivated", "GOLD IONIC", "2023+"],
        "description": (
            "INC Ransom is a ransomware and data extortion group active since at least July 2023. It is known for deploying "
            "INC Ransomware to encrypt and exfiltrate data, targeting industrial, healthcare, and education sectors across "
            "the United States and Europe. The group has used a combination of native tools, living-off-the-land binaries, "
            "and commercial remote access software to carry out its operations."
        ),
        "associated_groups": ["GOLD IONIC"],
        "campaigns": [],
        "techniques": [
            "T1087.002", "T1071", "T1560.001", "T1059.003", "T1486", "T1074", "T1190", "T1657", "T1562.001", "T1070.004",
            "T1105", "T1570", "T1036.005", "T1046", "T1135", "T1588.002", "T1069.002", "T1566", "T1219", "T1021.001",
            "T1049", "T1569.002", "T1537", "T1078", "T1047"
        ],
        "contributors": ["Matt Anderson", "@nosecurething", "Huntress"],
        "version": "1.0",
        "created": "06 June 2024",
        "last_modified": "28 October 2024",
        "navigator": "",
        "references": [
            {"source": "BleepingComputer", "url": "https://www.bleepingcomputer.com/news/security/inc-ransom-threatens-to-leak-3tb-of-nhs-scotland-stolen-data/"},
            {"source": "Cybereason", "url": "https://www.cybereason.com/blog/threat-alert-inc-ransomware"},
            {"source": "Secureworks CTU", "url": "https://www.secureworks.com/research/gold-ionic-deploys-inc-ransomware"},
            {"source": "SentinelOne", "url": "https://www.sentinelone.com/blog/what-is-inc-ransomware/"},
            {"source": "SOCRadar", "url": "https://socradar.io/dark-web-profile-inc-ransom/"},
            {"source": "Huntress", "url": "https://www.huntress.com/blog/investigating-new-inc-ransom-group-activity"},
            {"source": "Carvey, H.", "url": "https://www.heliosdigital.com/blog/lolbin-to-inc-ransomware"}
        ],
        "resources": [],
        "remediation": (
            "Implement strict RDP access control, disable unused remote access protocols, and monitor for LOLBin abuse such as "
            "SystemSettingsAdminFlows.exe. Regularly patch public-facing systems and deploy EDR solutions to detect and block "
            "PsExec, 7-Zip, and suspicious command-line behavior. Ensure offline backups are maintained and tested."
        ),
        "improvements": (
            "Deploy threat detection signatures for common ransomware tools like MegaSync and PsExec. Improve segmentation "
            "between production and administrative systems to reduce lateral movement opportunities. Integrate anomaly-based "
            "detections to identify encryption activity at scale."
        ),
        "hunt_steps": [
            "Search for usage of winupd.exe or PsExec in unusual contexts.",
            "Query for RDP connections made using valid but recently created accounts.",
            "Look for 7-Zip and WinRAR usage associated with large file transfers.",
            "Review recent use of AnyDesk, MegaSync, and other known tools in unexpected locations."
        ],
        "expected_outcomes": [
            "Detection of ransomware deployment and lateral movement via SMB or RDP.",
            "Identification of data staging and exfiltration behavior.",
            "Isolation of compromised accounts used for privilege escalation or remote execution."
        ],
        "false_positive": (
            "Legitimate use of administrative tools like PsExec or RDP may generate false positives; correlate with behavioral "
            "indicators like encryption or data staging to validate threats."
        ),
        "clearing_steps": [
            "Terminate malicious processes and isolate affected endpoints.",
            "Revoke compromised credentials and reimage infected systems.",
            "Purge persistence mechanisms and disable unauthorized services or scheduled tasks.",
            "Notify affected parties and begin incident response playbook including legal counsel."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
