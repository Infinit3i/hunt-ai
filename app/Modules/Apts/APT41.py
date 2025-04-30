def get_content():
    return {
        "id": "G0096",
        "url_id": "apt41",
        "title": "APT41",
        "tags": ["China", "state-sponsored", "financial", "dual-purpose", "cyberespionage", "APT41"],
        "description": (
            "APT41 is a Chinese state-sponsored threat group active since at least 2012. It uniquely blends "
            "espionage with financially motivated operations. APT41 has targeted various sectors globally, "
            "including healthcare, telecom, technology, education, and finance. The group is known for its "
            "versatility and vast toolset, including malware like DUSTPAN and KEYPLUG, and for its sophisticated "
            "supply chain and web server compromise tactics. It has overlapping activity with groups like BARIUM "
            "and Winnti."
        ),
        "associated_groups": ["Wicked Panda", "Brass Typhoon", "BARIUM"],
        "campaigns": ["APT41 DUST", "C0017"],
        "techniques": [
            "T1134", "T1087.001", "T1087.002", "T1098.007", "T1583.007", "T1595.002", "T1595.003", "T1071.001",
            "T1071.002", "T1071.004", "T1560.001", "T1560.003", "T1119", "T1197", "T1547.001", "T1037", "T1110",
            "T1059.001", "T1059.003", "T1059.004", "T1059.007", "T1586.003", "T1136.001", "T1543.003", "T1555",
            "T1555.003", "T1486", "T1213.003", "T1005", "T1001.003", "T1074.001", "T1030", "T1140", "T1484.001",
            "T1568.002", "T1573.002", "T1546.008", "T1480.001", "T1048.003", "T1041", "T1567.002", "T1190",
            "T1203", "T1133", "T1008", "T1083", "T1574.001", "T1574.006", "T1562.006", "T1656", "T1070.001",
            "T1070.003", "T1070.004", "T1105", "T1056.001", "T1570", "T1036.004", "T1036.005", "T1112", "T1104",
            "T1599", "T1046", "T1135", "T1027", "T1027.002", "T1027.013", "T1588.002", "T1588.003", "T1003.001",
            "T1003.002", "T1003.003", "T1069", "T1566.001", "T1542.003", "T1055", "T1090", "T1012", "T1021.001",
            "T1021.002", "T1018", "T1496.001", "T1014", "T1053.005", "T1596.005", "T1593.002", "T1594", "T1505.003",
            "T1553.002", "T1195.002", "T1218.001", "T1218.011", "T1082", "T1016", "T1049", "T1033", "T1569.002",
            "T1550.002", "T1078", "T1102.001", "T1047"
        ],
        "contributors": ["Kyaw Pyiyt Htet", "Nikita Rostovcev"],
        "version": "4.1",
        "created": "23 September 2019",
        "last_modified": "10 October 2024",
        "navigator": "https://attack.mitre.org/groups/G0096/",
        "references": [
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0096/"},
            {"source": "Mandiant", "url": "https://www.mandiant.com/resources/apt41-dual-espionage-and-cyber-crime"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/security/blog/2023/07/12/how-microsoft-names-threat-actors/"}
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
