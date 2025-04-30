def get_content():
    return {
        "id": "G0001",
        "url_id": "Axiom",
        "title": "Axiom",
        "tags": ["china", "cyberespionage", "aerospace", "defense", "media", "government", "advanced"],
        "description": "Axiom is a suspected Chinese cyber espionage group active since at least 2008. It has targeted a variety of sectors including aerospace, defense, manufacturing, media, and government. Some overlap has been observed with Winnti Group, though differences in TTPs and targeting suggest Axiom operates as a distinct group.",
        "associated_groups": ["Group 72"],
        "campaigns": [],
        "techniques": [
            "T1583.002", "T1583.003", "T1560", "T1584.005", "T1005", "T1001.002", "T1189", "T1546.008",
            "T1190", "T1203", "T1003", "T1566", "T1563.002", "T1021.001", "T1553", "T1078"
        ],
        "contributors": [],
        "version": "2.0",
        "created": "31 May 2017",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {"source": "Operation SMN Report", "url": "https://www.novetta.com/reports/operation-smn-axiom-threat-actor-group-report/"},
            {"source": "Kaspersky", "url": "https://securelist.com/winnti-more-than-just-a-game/57647/"},
            {"source": "Cisco Talos", "url": "https://blog.talosintelligence.com/group-72-zxshell/"},
            {"source": "Novetta", "url": "https://www.novetta.com/winnti-analysis"},
            {"source": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/2014/10/group-72-threat-spotlight.html"}
        ],
        "resources": [],
        "remediation": "Restrict administrative privileges, monitor for abnormal RDP sessions, disable accessibility features like Sticky Keys on servers, and validate digital certificates to prevent trust abuse. Employ strict egress filtering and monitor for data staging activities.",
        "improvements": "Enhance detection for steganography, unauthorized registry modifications, and credential dumping behavior. Use behavior-based detections for software persistence via accessibility features and known tools like gh0st RAT and PlugX.",
        "hunt_steps": [
            "Search for suspicious usage of Sticky Keys or accessibility executables",
            "Inspect RDP logs for hijacking or odd login patterns",
            "Hunt for encrypted outbound traffic possibly using steganography",
            "Look for abuse of trusted digital certificates",
            "Monitor for SQL injection exploitation attempts"
        ],
        "expected_outcomes": [
            "Identification of unauthorized remote sessions",
            "Detection of C2 channels hidden with steganography",
            "Recognition of credential theft and privilege escalation methods",
            "Surface obfuscated or staged exfiltration data",
            "Insights into watering hole and drive-by attack infrastructure"
        ],
        "false_positive": "Sticky Keys usage can be legitimate in accessibility contexts. Confirm the presence of administrative privilege abuse or anomalous access patterns before action.",
        "clearing_steps": [
            "Reset compromised admin credentials",
            "Remove malicious persistence mechanisms via registry or scheduled tasks",
            "Disable unnecessary remote access configurations",
            "Revoke abused digital certificates",
            "Patch vulnerable web-facing applications"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
