def get_content():
    return {
        "id": "G0103",
        "url_id": "Mofang",
        "title": "Mofang",
        "tags": ["china-based", "cyber espionage", "critical infrastructure", "government", "military"],
        "description": (
            "Mofang is a likely China-based cyber espionage group active since at least May 2012. "
            "The group is known for mimicking victim infrastructure and targeting governments and "
            "critical infrastructure, particularly in Myanmar. Their activities have also extended "
            "into military, automobile, and weapons industries."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": ["T1027.013", "T1027.015", "T1566.001", "T1566.002", "T1204.001", "T1204.002"],
        "contributors": [],
        "version": "1.1",
        "created": "12 May 2020",
        "last_modified": "11 April 2024",
        "navigator": "",
        "references": [
            {
                "source": "Yonathan Klijnsma",
                "url": "https://www.recordedfuture.com/mofang-politically-motivated-information-stealing-adversary"
            }
        ],
        "resources": [],
        "remediation": (
            "Implement spearphishing training for employees, apply attachment and link filtering in email systems, "
            "monitor for encoded/compressed payloads, and enforce multi-layered detection against known IOCs."
        ),
        "improvements": (
            "Enhance endpoint detection capabilities to decode compressed or encrypted payloads. "
            "Harden user execution environments to prevent exploitation via malicious file and link execution."
        ),
        "hunt_steps": [
            "Search for encrypted or compressed payload downloads in network traffic.",
            "Inspect email gateway logs for spearphishing attachments and links.",
            "Monitor execution from unexpected directories associated with spearphishing delivery."
        ],
        "expected_outcomes": [
            "Detection of ShimRat deployment or related payloads.",
            "Identification of spearphishing activity targeting government or defense sectors.",
            "Correlating obfuscated file indicators with suspicious user activity."
        ],
        "false_positive": (
            "Legitimate compression or encryption tools used by IT staff may resemble obfuscation techniques. "
            "Correlate with user behavior and context to reduce false alerts."
        ),
        "clearing_steps": [
            "Delete known malicious payloads (e.g., ShimRat variants).",
            "Revoke compromised credentials.",
            "Purge email accounts of related spearphishing messages.",
            "Audit system startup folders and registry run keys for persistence artifacts."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
