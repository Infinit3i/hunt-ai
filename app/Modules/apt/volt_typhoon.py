def get_content():
    return {
        "id": "G1017",  # APT Group ID
        "url_id": "G1017",  # URL segment for group reference
        "title": "Volt Typhoon",  # Name of the APT group
        "tags": ["state-sponsored", "critical infrastructure", "China", "APT"],
        "description": (
            "Volt Typhoon is a People's Republic of China (PRC) state-sponsored actor active since at least 2021, "
            "primarily targeting critical infrastructure organizations in the US and its territories including Guam. "
            "Their operations are assessed as pre-positioning for lateral movement to operational technology (OT) assets, "
            "employing stealth techniques, web shells, living-off-the-land (LOTL) binaries, hands-on-keyboard activities, "
            "and stolen credentials."
        ),
        "associated_groups": [
            "BRONZE SILHOUETTE",
            "Vanguard Panda",
            "DEV-0391",
            "UNC3236",
            "Voltzite",
            "Insidious Taurus"
        ],
        "campaigns": [
            {
                "id": "C0035",
                "name": "KV Botnet Activity",
                "first_seen": "October 2022",
                "last_seen": "January 2024",
                "references": ["https://attack.mitre.org/campaigns/C0035"]
            },
            {
                "id": "C0039",
                "name": "Versa Director Zero Day Exploitation",
                "first_seen": "June 2024",
                "last_seen": "August 2024",
                "references": ["https://attack.mitre.org/campaigns/C0039"]
            }
        ],
        "techniques": [
            "T1087.001", "T1087.002", "T1583.003", "T1071.001", "T1010", "T1560.001",
            "T1217", "T1059.001", "T1059.003", "T1059.004", "T1584.003", "T1584.004",
            "T1584.005", "T1584.008", "T1555.003", "T1005", "T1074.001", "T1587.001",
            "T1587.004", "T1006", "T1573.001", "T1573.002", "T1546", "T1190", "T1068",
            "T1133", "T1083", "T1222.002", "T1592", "T1589.002", "T1590.004", "T1590.006",
            "T1591.004", "T1562.001", "T1070.001", "T1070.004", "T1105", "T1056.001",
            "T1570", "T1654", "T1036.004", "T1036.005", "T1036.008", "T1112", "T1046",
            "T1095", "T1571", "T1027.002", "T1588.002", "T1588.006", "T1003.001",
            "T1003.003", "T1120", "T1069.001", "T1069.002", "T1057", "T1055.009",
            "T1090.001", "T1090.003", "T1012", "T1021.001", "T1018", "T1113",
            "T1596.005", "T1593", "T1594", "T1505.003", "T1518.001", "T1218", "T1082",
            "T1614", "T1016", "T1049", "T1033", "T1007", "T1124", "T1552.004",
            "T1078.002", "T1497.001", "T1047"
        ],
        "contributors": [
            "Phyo Paing Htun (ChiLai)",
            "I-Secure Co.,Ltd",
            "Ai Kimura, NEC Corporation",
            "Manikantan Srinivasan, NEC Corporation India",
            "Pooja Natarajan, NEC Corporation India"
        ],
        "version": "2.0",
        "created": "27 July 2023",
        "last_modified": "21 May 2024",
        "references": [
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G1017/"},
            {"source": "CISA", "url": "https://www.cisa.gov/"},
            {"source": "Microsoft Threat Intelligence", "url": "https://www.microsoft.com/"},
            {"source": "NSA", "url": "https://www.nsa.gov/"},
            {"source": "Counter Threat Unit Research Team", "url": "https://www.example.com/"},
            {"source": "Black Lotus Labs", "url": "https://www.blacklotuslabs.com/"},
            {"source": "US Department of Justice", "url": "https://www.justice.gov/"}
        ],
        "resources": [
            "https://attack.mitre.org/groups/G1017/"
        ],
        "remediation": "",  # Recommended actions to mitigate risks posed by this APT
        "improvements": "",  # Suggestions for enhancing detection and response related to this APT
        "hunt_steps": [],  # Proactive threat hunting steps to look for indicators of this APT
        "expected_outcomes": [],  # Expected outcomes/results from threat hunting against this APT
        "false_positive": "",  # Known false positives and guidance on handling them
        "clearing_steps": [],  # Steps for remediation and clearing traces from affected systems
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [],  # List of SHA256 hash values
            "md5": [],     # List of MD5 hash values
            "ip": [],      # List of IP addresses associated with the APT
            "domain": [],  # List of domains associated with the APT
            "resources": []  # Additional resources or references for IOCs if applicable
        }
    }
