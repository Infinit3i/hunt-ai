def get_content():
    return {
        "id": "G1004",
        "url_id": "LAPSUS",
        "title": "LAPSUS$",
        "tags": ["cybercrime", "social engineering", "data extortion", "insider threat"],
        "description": (
            "LAPSUS$ is a financially motivated cybercriminal group active since at least mid-2021. "
            "It is known for bold and disruptive social engineering, data exfiltration, and extortion operations against global organizations. "
            "They target a wide range of sectors including technology, telecom, government, energy, and healthcare, often without using ransomware. "
            "The group has employed methods like SIM swapping, bribing insiders, MFA fatigue attacks, DNS hijacking, and cloud persistence to gain and maintain access to sensitive systems."
        ),
        "associated_groups": ["DEV-0537", "Strawberry Tempest"],
        "campaigns": [],
        "techniques": [
            "T1531", "T1087.002", "T1098.003", "T1583.003", "T1586.002", "T1584.002", "T1136.003", "T1555.003", "T1555.005",
            "T1485", "T1213.001", "T1213.002", "T1213.003", "T1213.005", "T1005", "T1114.003", "T1068", "T1133", "T1589",
            "T1589.001", "T1589.002", "T1591.002", "T1591.004", "T1656", "T1578.002", "T1578.003", "T1111", "T1621", "T1588.001",
            "T1588.002", "T1003.003", "T1003.006", "T1069.002", "T1598.004", "T1090", "T1597.002", "T1593.003", "T1489",
            "T1199", "T1552.008", "T1204", "T1078", "T1078.004", "T1451"
        ],
        "contributors": [
            "David Hughes, BT Security",
            "Matt Brenton, Zurich Insurance Group",
            "Flavio Costa, Cisco",
            "Caio Silva"
        ],
        "version": "2.1",
        "created": "09 June 2022",
        "last_modified": "07 April 2025",
        "navigator": "https://attack.mitre.org/groups/G1004/",
        "references": [
            {"source": "BBC", "url": "https://www.bbc.com/news/technology-60993047"},
            {"source": "Microsoft", "url": "https://www.microsoft.com/security/blog/2022/03/24/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/"},
            {"source": "Palo Alto Networks", "url": "https://unit42.paloaltonetworks.com/lapsus-threat-brief/"},
            {"source": "Krebs on Security", "url": "https://krebsonsecurity.com/2022/03/a-closer-look-at-the-lapsus-data-extortion-group/"}
        ],
        "resources": [
            "https://www.microsoft.com/security/blog/2022/03/24/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/",
            "https://krebsonsecurity.com/2022/03/a-closer-look-at-the-lapsus-data-extortion-group/"
        ],
        "remediation": (
            "Enforce strict MFA, monitor for abnormal help desk requests, restrict admin privileges, "
            "audit DNS changes, and limit cloud administrative permissions. Implement anomaly-based detection "
            "for account creation, role escalation, and unusual authentication behavior."
        ),
        "improvements": (
            "Strengthen internal training against social engineering, simulate help desk fraud scenarios, "
            "deploy conditional access policies, and enhance visibility into insider behavior and third-party relationships."
        ),
        "hunt_steps": [
            "Monitor for new global admin account creation in cloud environments",
            "Search DNS logs for unauthorized record changes",
            "Review cloud audit logs for privilege escalation events",
            "Detect MFA request floods or repeated approvals"
        ],
        "expected_outcomes": [
            "Identification of compromised cloud accounts and privileged access abuse",
            "Detection of infrastructure modifications such as DNS hijacking and VM deletion",
            "Prevention of data exfiltration and internal sabotage via insider collusion",
            "Increased detection coverage across help desk workflows and MFA approvals"
        ],
        "false_positive": (
            "Certain cloud operations and account creations may be legitimate. Contextual validation with time, user behavior, and source IP is necessary."
        ),
        "clearing_steps": [
            "Revoke unauthorized cloud permissions and reset all affected credentials",
            "Remove rogue DNS records and validate current configurations",
            "Delete unauthorized VMs and terminate abnormal sessions",
            "Restore impacted systems from secure backups and audit admin access logs"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://unit42.paloaltonetworks.com/lapsus-threat-brief/",
                "https://krebsonsecurity.com/2022/03/a-closer-look-at-the-lapsus-data-extortion-group/"
            ]
        }
    }
