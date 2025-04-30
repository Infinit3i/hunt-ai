def get_content():
    return {
        "id": "G0050",
        "url_id": "apt32",
        "title": "APT32",
        "tags": ["Vietnamese", "espionage", "state-sponsored"],
        "description": (
            "APT32 is a suspected Vietnam-based threat group that has been active since at least 2014. "
            "The group has targeted multiple private sector industries as well as foreign governments, dissidents, "
            "and journalists with a strong focus on Southeast Asian countries like Vietnam, the Philippines, Laos, and Cambodia. "
            "They have extensively used strategic web compromises to compromise victims."
        ),
        "associated_groups": [
            "SeaLotus", "OceanLotus", "APT-C-00", "Canvas Cyclone", "BISMUTH"
        ],
        "campaigns": [],
        "techniques": [
            "T1087.001", "T1583.001", "T1583.006", "T1071.001", "T1071.003", "T1560",
            "T1547.001", "T1059", "T1059.001", "T1059.003", "T1059.005", "T1059.007",
            "T1543.003", "T1189", "T1585.001", "T1048.003", "T1041", "T1203", "T1068",
            "T1083", "T1222.002", "T1589", "T1589.002", "T1564.001", "T1564.003", "T1564.004",
            "T1574.001", "T1070.001", "T1070.004", "T1070.006", "T1105", "T1056.001",
            "T1570", "T1036", "T1036.003", "T1036.004", "T1036.005", "T1112", "T1046",
            "T1135", "T1571", "T1027.010", "T1027.011", "T1027.013", "T1027.016",
            "T1588.002", "T1137", "T1003", "T1003.001", "T1566.001", "T1566.002",
            "T1598.003", "T1055", "T1012", "T1021.002", "T1018", "T1053.005", "T1505.003",
            "T1072", "T1608.001", "T1608.004", "T1218.005", "T1218.010", "T1218.011",
            "T1082", "T1016", "T1049", "T1033", "T1216.001", "T1569.002", "T1552.002",
            "T1550.002", "T1550.003", "T1204.001", "T1204.002", "T1078.003", "T1102",
            "T1047"
        ],
        "contributors": ["Romain Dumont", "ESET"],
        "version": "3.0",
        "created": "14 December 2017",
        "last_modified": "17 April 2024",
        "navigator": "https://attack.mitre.org/groups/G0050/",
        "references": [
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0050/"},
            {"source": "ESET", "url": "https://www.welivesecurity.com/en/eset-research/apt32-report"}
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
