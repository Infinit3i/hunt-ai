def get_content():
    return {
        "id": "G0065",
        "url_id": "Leviathan",
        "title": "Leviathan",
        "tags": ["china", "state-sponsored", "espionage", "APT40", "maritime", "credential access"],
        "description": (
            "Leviathan is a Chinese state-sponsored cyber espionage group attributed to the Ministry of State Security's (MSS) "
            "Hainan State Security Department. Active since at least 2009, Leviathan has targeted a wide range of sectors globally, "
            "including academia, defense, government, healthcare, and transportation. The group is associated with multiple aliases, "
            "including APT40, TEMP.Periscope, and MUDCARP. Leviathan is known for its extensive use of public and custom tools, web shells, "
            "and exploitation of vulnerabilities for initial access, privilege escalation, and lateral movement."
        ),
        "associated_groups": ["MUDCARP", "Kryptonite Panda", "Gadolinium", "BRONZE MOHAWK", "TEMP.Jumper", "APT40", "TEMP.Periscope", "Gingham Typhoon"],
        "campaigns": ["C0049"],
        "techniques": [
            "T1583.001", "T1595.002", "T1560", "T1197", "T1547.001", "T1547.009", "T1059.001", "T1059.005", "T1586.001", "T1586.002",
            "T1584.004", "T1584.008", "T1213", "T1074.001", "T1074.002", "T1140", "T1587.004", "T1482", "T1189", "T1585.001", "T1585.002",
            "T1546.003", "T1041", "T1567.002", "T1190", "T1203", "T1212", "T1068", "T1133", "T1589.001", "T1615", "T1562.004", "T1105",
            "T1056", "T1559.002", "T1534", "T1111", "T1135", "T1027.001", "T1027.003", "T1027.013", "T1027.015", "T1588.006", "T1003",
            "T1003.001", "T1566.001", "T1566.002", "T1055.001", "T1572", "T1090.003", "T1021.001", "T1021.002", "T1021.004", "T1018",
            "T1594", "T1505.003", "T1528", "T1558.003", "T1553.002", "T1218.010", "T1082", "T1552", "T1552.001", "T1204.001",
            "T1204.002", "T1078", "T1078.002", "T1078.003", "T1102.003", "T1047"
        ],
        "contributors": ["Valerii Marchuk, Cybersecurity Help s.r.o."],
        "version": "4.1",
        "created": "18 April 2018",
        "last_modified": "03 February 2025",
        "navigator": "https://attack.mitre.org/groups/G0065/",
        "references": [
            {"source": "CISA", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-200a"},
            {"source": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/2018/03/suspected-chinese-cyber-espionage-group-tempperiscope.html"},
            {"source": "CISA et al.", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/2024/07/08/apt40-tradecraft"}
        ],
        "resources": [
            "https://attack.mitre.org/groups/G0065/",
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-200a"
        ],
        "remediation": (
            "Apply rigorous vulnerability management, monitor for signs of credential misuse, harden externally facing systems, and restrict use of remote services."
        ),
        "improvements": (
            "Implement Zero Trust architecture, enhance multi-factor authentication across services, and maintain comprehensive endpoint logging with long retention."
        ),
        "hunt_steps": [
            "Look for use of regsvr32, PowerShell, and VBScript executing from user directories",
            "Detect abnormal connections to Dropbox and web shells in application server logs",
            "Scan internal DNS logs for signs of SOHO device callbacks and dynamic DNS use",
            "Review staging directories such as C:\\Windows\\Debug for large file drops"
        ],
        "expected_outcomes": [
            "Reduced dwell time of intrusions through early detection",
            "Identification of credential theft and exfiltration behaviors",
            "Visibility into staging behaviors and internal reconnaissance"
        ],
        "false_positive": (
            "Tools like regsvr32 and PowerShell may be used legitimately. Correlate execution context, parent-child process relationships, and file paths."
        ),
        "clearing_steps": [
            "Reset compromised credentials and review lateral movement paths",
            "Remove persistence mechanisms like WMI subscriptions and shortcut links",
            "Patch all externally facing services and validate firewall rules",
            "Remove dropped web shells and restore affected systems"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://attack.mitre.org/groups/G0065/",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-200a"
            ]
        }
    }
