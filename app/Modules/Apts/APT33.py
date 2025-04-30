def get_content():
    return {
        "id": "G0064",
        "url_id": "apt33",
        "title": "APT33",
        "tags": ["Iranian", "state-sponsored", "espionage", "energy", "aviation"],
        "description": (
            "APT33 is a suspected Iranian threat group that has carried out operations since at least 2013. "
            "The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, "
            "with a particular interest in the aviation and energy sectors."
        ),
        "associated_groups": ["HOLMIUM", "Elfin", "Peach Sandstorm"],
        "campaigns": [],
        "techniques": [
            "T1071.001", "T1560.001", "T1547.001", "T1110.003", "T1059.001", "T1059.005",
            "T1555", "T1555.003", "T1132.001", "T1573.001", "T1546.003", "T1048.003",
            "T1203", "T1068", "T1105", "T1040", "T1571", "T1027.013", "T1588.002",
            "T1003.001", "T1003.004", "T1003.005", "T1566.001", "T1566.002", "T1053.005",
            "T1552.001", "T1552.006", "T1204.001", "T1204.002", "T1078", "T1078.004",
            "T0852", "T0853", "T0865"
        ],
        "contributors": ["Dragos Threat Intelligence"],
        "version": "2.0",
        "created": "18 April 2018",
        "last_modified": "11 April 2024",
        "navigator": "https://attack.mitre.org/groups/G0064/",
        "references": [
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0064/"},
            {"source": "Dragos", "url": "https://www.dragos.com/blog/threat-group-apt33-analysis/"}
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
