def get_content():
    return {
        "id": "G0059",
        "url_id": "Magic_Hound",
        "title": "Magic Hound",
        "tags": ["Iranian-sponsored", "cyber espionage", "long-term operations"],
        "description": "Magic Hound is an Iranian-sponsored threat group likely aligned with the Islamic Revolutionary Guard Corps. It has conducted sophisticated cyber espionage operations since at least 2014, targeting government, military, academic, and health organizations, including the WHO. The group is known for complex social engineering and spearphishing campaigns.",
        "associated_groups": [
            "TA453", "COBALT ILLUSION", "Charming Kitten", "ITG18",
            "Phosphorus", "Newscaster", "APT35", "Mint Sandstorm"
        ],
        "campaigns": [],
        "techniques": [
            "T1087.003", "T1098.002", "T1098.007", "T1583.001", "T1583.006", "T1595.002",
            "T1071", "T1071.001", "T1560.001", "T1547.001", "T1059.001", "T1059.003",
            "T1059.005", "T1586.002", "T1584.001", "T1136.001", "T1486", "T1005", "T1482",
            "T1189", "T1114", "T1114.001", "T1114.002", "T1573", "T1585.001", "T1585.002",
            "T1567", "T1190", "T1083", "T1592.002", "T1589", "T1589.001", "T1589.002",
            "T1590.005", "T1591.001", "T1564.003", "T1562", "T1562.001", "T1562.002",
            "T1562.004", "T1070.003", "T1070.004", "T1105", "T1056.001", "T1570", "T1036.004",
            "T1036.005", "T1036.010", "T1112", "T1046", "T1571", "T1027.010", "T1027.013",
            "T1588.002", "T1003.001", "T1566.002", "T1566.003", "T1598.003", "T1057", "T1572",
            "T1090", "T1021.001", "T1018", "T1053.005", "T1113", "T1505.003", "T1218.011",
            "T1082", "T1016", "T1016.001", "T1016.002", "T1049", "T1033", "T1204.001",
            "T1204.002", "T1078.001", "T1078.002", "T1102.002", "T1047"
        ],
        "contributors": ["Anastasios Pingios", "Bryan Lee", "Daniyal Naeem, BT Security"],
        "version": "6.1",
        "created": "16 January 2018",
        "last_modified": "17 November 2024",
        "navigator": "",  # Can be filled with a URL if a navigator layer is available
        "references": [
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0059/"},
            {"source": "Check Point", "url": "https://research.checkpoint.com"},
            {"source": "MSTIC", "url": "https://www.microsoft.com/security/blog"}
        ],
        "resources": [
            "https://attack.mitre.org/groups/G0059/",
            "https://www.clearskysec.com/charming-kitten/",
            "https://www.secureworks.com/research/threat-profiles/cobalt-illusion"
        ],
        "remediation": "Implement application whitelisting, monitor and restrict use of PowerShell, deploy endpoint detection and response (EDR) tools, and segment networks to minimize lateral movement.",
        "improvements": "Enhance phishing detection, improve mail filtering, educate users on social engineering risks, and implement behavioral monitoring on endpoints.",
        "hunt_steps": [
            "Look for PowerShell scripts with base64-encoded commands",
            "Monitor for usage of rundll32 with comsvcs.dll",
            "Identify anomalous mailbox export requests in Exchange logs",
            "Inspect creation of local accounts like 'DefaultAccount' or 'help'"
        ],
        "expected_outcomes": [
            "Detection of unauthorized mailbox access",
            "Identification of suspicious PowerShell activity",
            "Discovery of adversary-created user accounts",
            "Alerts on potential C2 traffic over non-standard ports"
        ],
        "false_positive": "Legitimate admin tools (e.g., PowerShell, RDP) may resemble adversary use. Validate against expected behavior and timing patterns.",
        "clearing_steps": [
            "Disable and remove unauthorized user accounts",
            "Restore firewall rules to default",
            "Re-enable and configure LSA protection",
            "Audit and clean Exchange mailbox export history"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://www.mandiant.com/resources/m-trends-2018",
                "https://www.clearskysec.com/the-kittens-are-back-in-town/",
                "https://www.microsoft.com/security/blog/2021/11/16/evolving-trends-in-iranian-threat-actor-activity"
            ]
        }
    }
