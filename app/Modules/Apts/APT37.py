def get_content():
    return {
        "id": "G0067",
        "url_id": "apt37",
        "title": "APT37",
        "tags": ["North Korea", "state-sponsored", "cyber espionage", "destructive malware"],
        "description": (
            "APT37 is a North Korean state-sponsored cyber espionage group that has been active since at least 2012. "
            "The group has targeted victims primarily in South Korea, but also in Japan, Vietnam, Russia, Nepal, China, "
            "India, Romania, Kuwait, and other parts of the Middle East. They have also been linked to a number of campaigns, "
            "including Operation Daybreak, Erebus, Golden Time, Evil New Year, and others between 2016-2018."
        ),
        "associated_groups": [
            "InkySquid", "ScarCruft", "Reaper", "Group123", "TEMP.Reaper", "Ricochet Chollima"
        ],
        "campaigns": [],
        "techniques": [
            "T1548.002", "T1071.001", "T1123", "T1547.001", "T1059", "T1059.003", "T1059.005", "T1059.006",
            "T1555.003", "T1005", "T1561.002", "T1189", "T1203", "T1105", "T1559.002", "T1036.001", "T1106",
            "T1027", "T1027.003", "T1120", "T1566.001", "T1057", "T1055", "T1053.005", "T1082", "T1033",
            "T1529", "T1204.002", "T1102.002"
        ],
        "contributors": ["Valerii Marchuk", "Cybersecurity Help s.r.o."],
        "version": "2.0",
        "created": "18 April 2018",
        "last_modified": "17 November 2024",
        "navigator": "https://attack.mitre.org/groups/G0067/",
        "references": [
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0067/"}
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
