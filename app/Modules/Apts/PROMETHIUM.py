def get_content():
    return {
        "id": "G0056",
        "url_id": "PROMETHIUM",
        "title": "PROMETHIUM",
        "tags": ["espionage", "state-sponsored", "turkey", "strongpity", "global-operations"],
        "description": (
            "PROMETHIUM is an espionage-focused activity group active since at least 2012, with global operations "
            "and a particular emphasis on Turkish targets. The group has significant overlap with the activity group "
            "NEODYMIUM, sharing victimology and campaign characteristics. PROMETHIUM is known for its use of the "
            "StrongPity malware family, which includes mobile and desktop implants capable of advanced surveillance "
            "and data exfiltration operations."
        ),
        "associated_groups": ["StrongPity"],
        "campaigns": [
            {
                "id": "C0033",
                "name": "C0033",
                "first_seen": "May 2016",
                "last_seen": "January 2023",
                "references": [
                    "https://www.welivesecurity.com/2023/01/10/strongpity-espionage-campaign-targeting-android-users/",
                    "https://securelist.com/on-the-strongpity-waterhole-attacks/76148/",
                    "https://unit42.paloaltonetworks.com/strongpity-apt-group-deploys-android-malware/"
                ]
            }
        ],
        "techniques": [
            "T1547.001", "T1543.003", "T1587.002", "T1587.003", "T1189", "T1036.004", "T1036.005",
            "T1553.002", "T1205.001", "T1204.002", "T1078.003", "T1517", "T1437.001", "T1532",
            "T1429", "T1456", "T1521.001", "T1624.001", "T1646", "T1420", "T1629.003", "T1544",
            "T1430", "T1655.001", "T1406", "T1636.002", "T1636.003", "T1636.004", "T1418", "T1426", "T1421"
        ],
        "contributors": ["MITRE ATT&CK Team"],
        "version": "2.1",
        "created": "16 January 2018",
        "last_modified": "19 April 2024",
        "navigator": "",
        "references": [
            {"source": "Microsoft", "url": "https://www.microsoft.com/security/blog/2016/12/14/twin-zero-day-attacks-promethium-and-neodymium/"},
            {"source": "WeLiveSecurity", "url": "https://www.welivesecurity.com/2023/01/10/strongpity-espionage-campaign-targeting-android-users/"},
            {"source": "Securelist", "url": "https://securelist.com/on-the-strongpity-waterhole-attacks/76148/"},
            {"source": "Palo Alto Networks", "url": "https://unit42.paloaltonetworks.com/strongpity-apt-group-deploys-android-malware/"}
        ],
        "resources": [],
        "remediation": (
            "Implement application allow-listing to prevent execution of unauthorized binaries, "
            "regularly patch systems to reduce drive-by compromise risk, and deploy certificate trust policies to detect "
            "and prevent use of self-signed code."
        ),
        "improvements": (
            "Improve logging and alerting on service creation, registry modification, and port knocking behavior. "
            "Deploy mobile device management (MDM) tools for tighter control and visibility over mobile threats."
        ),
        "hunt_steps": [
            "Search for suspicious registry key modifications indicating persistence.",
            "Look for creation of services with anomalous names or linked binaries.",
            "Hunt for signs of self-signed certificate usage in the environment.",
            "Identify network traffic showing signs of port knocking or HTTPS-based exfiltration.",
            "Review logs for application installations outside of standard channels."
        ],
        "expected_outcomes": [
            "Detection of unauthorized persistence mechanisms.",
            "Identification of malware disguised as legitimate software installers.",
            "Discovery of indicators of mobile compromise and surveillance tooling.",
            "Visibility into encrypted exfiltration behavior and port-knocking patterns."
        ],
        "false_positive": (
            "Registry and service creation may occur during legitimate software installation. Correlate with software inventory, "
            "time of installation, and expected behavior."
        ),
        "clearing_steps": [
            "Remove malicious services and registry run keys.",
            "Revoke self-signed certificates and reset trusted root certificate lists where compromised.",
            "Reimage compromised devices, both mobile and desktop.",
            "Notify affected users and reset credentials, especially local admin accounts."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
