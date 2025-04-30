def get_content():
    return {
        "id": "G0082",
        "url_id": "apt38",
        "title": "APT38",
        "tags": ["North Korea", "state-sponsored", "financial cybercrime", "destructive malware"],
        "description": (
            "APT38 is a North Korean state-sponsored threat group that specializes in financial cyber operations; "
            "it has been attributed to the Reconnaissance General Bureau. Active since at least 2014, APT38 has "
            "targeted banks, financial institutions, casinos, cryptocurrency exchanges, SWIFT system endpoints, "
            "and ATMs in at least 38 countries worldwide. Notable operations include the 2016 Bank of Bangladesh "
            "heist, where $81 million was stolen, as well as destructive attacks against Bancomext and Banco de Chile."
        ),
        "associated_groups": [
            "NICKEL GLADSTONE", "BeagleBoyz", "Bluenoroff",
            "Stardust Chollima", "Sapphire Sleet", "COPERNICIUM"
        ],
        "campaigns": [],
        "techniques": [
            "T1548.002", "T1583.001", "T1071.001", "T1217", "T1110",
            "T1115", "T1059.001", "T1059.003", "T1059.005", "T1543.003",
            "T1485", "T1486", "T1005", "T1565.001", "T1565.002", "T1565.003",
            "T1140", "T1561.002", "T1189", "T1480.002", "T1083", "T1562.001",
            "T1562.003", "T1562.004", "T1070.001", "T1070.004", "T1070.006",
            "T1105", "T1056.001", "T1036.003", "T1036.006", "T1112", "T1106",
            "T1135", "T1027.002", "T1588.002", "T1566.001", "T1057", "T1055",
            "T1053.003", "T1053.005", "T1505.003", "T1518.001", "T1553.005",
            "T1218.001", "T1218.005", "T1218.007", "T1218.011", "T1082",
            "T1049", "T1033", "T1569.002", "T1529", "T1204.001", "T1204.002"
        ],
        "contributors": [
            "Hiroki Nagahama, NEC Corporation",
            "Manikantan Srinivasan, NEC Corporation India",
            "Pooja Natarajan, NEC Corporation India"
        ],
        "version": "3.1",
        "created": "29 January 2019",
        "last_modified": "22 January 2025",
        "navigator": "https://attack.mitre.org/groups/G0082/",
        "references": [
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0082/"}
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
